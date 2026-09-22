use std::time::Duration;

use paykit_server::{
    Server,
    config::{Config, ConfigEnvironment},
    startup::initialize_database,
};

const KEY: &str = "pubky7ir1ttte48bcp4zjychjyscicrwi1j34mtt91ptsafdbjmr8g9eo";
const MASTER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

fn clone_config(runtime_database_url: String, migrator_database_url: String) -> Config {
    Config::from_toml_and_environment(
        &format!(
            r#"
[http]
listen_addr = "127.0.0.1:0"
[locks]
trusted_public_key = "{KEY}"
[setup]
allowed_origins = ["https://app.example"]
[paykit]
receiver_path = "paykit/server"
network = "mainnet"
client_id = "paykit-server"
[bitcoin]
network = "mainnet"
creation_enabled = false
[deployment]
stack_role = "production"
[electrum]
endpoint = "ssl://electrum.example:50002"
[outbox]
poll_interval = "5s"
"#
        ),
        ConfigEnvironment {
            database_url: Some(runtime_database_url),
            migrator_database_url: Some(migrator_database_url),
            master_key: Some(MASTER_KEY.to_owned()),
            ..Default::default()
        },
    )
    .expect("production-clone rehearsal config is valid")
}

/// Invoked only by scripts/rehearse-production-schema-clone.sh.
///
/// Both URLs intentionally authenticate as the restored production owner in
/// this transitional image. The real startup path still closes the migrator
/// pool before opening the runtime pool; a later cutover supplies a LOGIN
/// member of the NOLOGIN `paykit` group as the runtime URL.
#[tokio::test]
#[ignore = "requires an explicitly prepared production-schema clone"]
async fn production_schema_clone_runs_real_startup_and_server_composition() {
    let migrator_database_url = std::env::var("PAYKIT_CLONE_MIGRATOR_DATABASE_URL")
        .expect("PAYKIT_CLONE_MIGRATOR_DATABASE_URL is required");
    let runtime_database_url = std::env::var("PAYKIT_CLONE_RUNTIME_DATABASE_URL")
        .expect("PAYKIT_CLONE_RUNTIME_DATABASE_URL is required");
    let config = clone_config(runtime_database_url, migrator_database_url);

    let initialized = initialize_database(&config)
        .await
        .expect("real database initialization succeeds on the clone");
    let versions: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&initialized.pool)
            .await
            .unwrap();
    assert_eq!(versions, (1..=26).collect::<Vec<_>>());

    let role_attributes: (bool, bool, bool, bool, bool, bool, bool) = sqlx::query_as(
        "SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolinherit,
                rolreplication, rolbypassrls
         FROM pg_catalog.pg_roles
         WHERE rolname = 'paykit'",
    )
    .fetch_one(&initialized.pool)
    .await
    .expect("migration 0024 created paykit");
    assert_eq!(
        role_attributes,
        (false, false, false, false, false, false, false)
    );

    for (object, privilege) in [("public", "USAGE"), ("public._sqlx_migrations", "SELECT")] {
        let granted: bool = if object == "public" {
            sqlx::query_scalar("SELECT has_schema_privilege('paykit', $1, $2)")
                .bind(object)
                .bind(privilege)
                .fetch_one(&initialized.pool)
                .await
                .unwrap()
        } else {
            sqlx::query_scalar("SELECT has_table_privilege('paykit', $1, $2)")
                .bind(object)
                .bind(privilege)
                .fetch_one(&initialized.pool)
                .await
                .unwrap()
        };
        assert!(granted, "paykit lacks {privilege} on {object}");
    }

    for privilege in ["SELECT", "INSERT", "UPDATE"] {
        let granted: bool = sqlx::query_scalar(
            "SELECT has_table_privilege('paykit', 'public.observer_leadership', $1)",
        )
        .bind(privilege)
        .fetch_one(&initialized.pool)
        .await
        .unwrap();
        assert!(granted, "paykit lacks {privilege} on observer_leadership");
    }
    for privilege in ["DELETE", "TRUNCATE"] {
        let granted: bool = sqlx::query_scalar(
            "SELECT has_table_privilege('paykit', 'public.observer_leadership', $1)",
        )
        .bind(privilege)
        .fetch_one(&initialized.pool)
        .await
        .unwrap();
        assert!(
            !granted,
            "paykit unexpectedly has {privilege} on observer_leadership"
        );
    }

    let readonly_select: bool = sqlx::query_scalar(
        "SELECT has_table_privilege('paykit_readonly', 'public.observer_leadership', 'SELECT')",
    )
    .fetch_one(&initialized.pool)
    .await
    .unwrap();
    assert!(
        readonly_select,
        "paykit_readonly lacks SELECT on observer_leadership"
    );
    for privilege in ["INSERT", "UPDATE", "DELETE"] {
        let granted: bool = sqlx::query_scalar(
            "SELECT has_table_privilege('paykit_readonly', 'public.observer_leadership', $1)",
        )
        .bind(privilege)
        .fetch_one(&initialized.pool)
        .await
        .unwrap();
        assert!(
            !granted,
            "paykit_readonly unexpectedly has {privilege} on observer_leadership"
        );
    }

    let server = Server::build(config, initialized.pool.clone(), initialized.stack_identity)
        .await
        .expect("real Server composition builds");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind disposable rehearsal listener");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let running = tokio::spawn(server.run_until(listener, async {
        let _ = shutdown_rx.await;
    }));
    tokio::task::yield_now().await;
    shutdown_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), running)
        .await
        .expect("server rehearsal shuts down")
        .expect("server rehearsal task joins")
        .expect("server rehearsal runs");

    initialized.pool.close().await;
}
