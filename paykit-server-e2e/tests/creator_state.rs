use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use paykit_sdk::PaykitIdentitySecretKey;
use paykit_server::{
    config::{Config, ConfigEnvironment},
    crypto::Crypto,
    domain::locks::parse_creator,
    persistence::{
        CreatorCredentials, CreatorStore, DeploymentStore, PersistenceError, run_migrations,
    },
    startup::initialize_database,
};
use paykit_server_e2e::postgres::TestDatabase;
use sqlx::Row;
use url::Url;

const KEY: &str = "pubky7ir1ttte48bcp4zjychjyscicrwi1j34mtt91ptsafdbjmr8g9eo";
const MASTER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const WRONG_MASTER_KEY: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI";
const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";
const OTHER_CREATOR: &str = "pubky7ir1ttte48bcp4zjychjyscicrwi1j34mtt91ptsafdbjmr8g9eo";
const SESSION: &str = "session-secret-sentinel";
const XPUB: &str = "xpub-sentinel";
const OTHER_SESSION: &str = "other-session";
const OTHER_XPUB: &str = "other-xpub";

fn config_with_secrets(network: &str, database_url: &str, master_key: &str) -> Config {
    Config::from_toml_and_environment(
        &format!(
            r#"
[http]
listen_addr = "127.0.0.1:8080"
[locks]
trusted_public_key = "{KEY}"
[setup]
allowed_origins = ["https://app.example"]
[paykit]
client_id = "app.paykit.server"
app_id = "paykit-server"
network = "testnet"
[bitcoin]
network = "{network}"
[electrum]
endpoint = "ssl://electrum.example:50002"
[outbox]
poll_interval = "5s"
"#
        ),
        ConfigEnvironment {
            database_url: Some(database_url.to_owned()),
            master_key: Some(master_key.to_owned()),
        },
    )
    .expect("valid config fixture")
}

fn config(network: &str) -> Config {
    config_with_secrets(
        network,
        "postgres://paykit:secret@localhost/paykit",
        MASTER_KEY,
    )
}

fn crypto() -> Arc<Crypto> {
    Arc::new(Crypto::from_master_key([1; 32].as_slice()).unwrap())
}
fn creator() -> paykit_server::domain::locks::CreatorPubky {
    parse_creator(CREATOR).unwrap()
}
fn other_creator() -> paykit_server::domain::locks::CreatorPubky {
    parse_creator(OTHER_CREATOR).unwrap()
}
fn credentials_for(
    creator: paykit_server::domain::locks::CreatorPubky,
    session: &str,
    xpub: &str,
    index: u32,
    noise: [u8; 32],
) -> CreatorCredentials {
    CreatorCredentials::new(
        creator,
        session.to_owned(),
        PaykitIdentitySecretKey::new(noise, 1).unwrap(),
        Some(paykit_server::domain::receiving::BitcoinAccount {
            xpub: xpub.to_owned().into(),
            account_index: index,
        }),
        None,
    )
}
fn credentials(session: &str, xpub: &str, index: u32, noise: [u8; 32]) -> CreatorCredentials {
    credentials_for(creator(), session, xpub, index, noise)
}

async fn stores(database: &TestDatabase) -> CreatorStore {
    run_migrations(database.pool()).await.unwrap();
    CreatorStore::new(database.pool(), crypto())
}

fn assert_startup_error_is_redacted(
    error: &(impl std::fmt::Display + std::fmt::Debug),
    database_url: &str,
) {
    let parsed_database_url = Url::parse(database_url).unwrap();
    let mut sensitive = vec![
        CREATOR,
        OTHER_CREATOR,
        SESSION,
        XPUB,
        OTHER_SESSION,
        OTHER_XPUB,
        MASTER_KEY,
        WRONG_MASTER_KEY,
        database_url,
        "corrupt-creator-envelope",
        "corrupt-sdk-state",
    ];
    if !parsed_database_url.username().is_empty() {
        sensitive.push(parsed_database_url.username());
    }
    if let Some(password) = parsed_database_url.password() {
        sensitive.push(password);
    }

    for message in [error.to_string(), format!("{error:?}")] {
        for sensitive in &sensitive {
            assert!(
                !message.contains(sensitive),
                "startup error exposed sensitive state"
            );
        }
    }
}

#[tokio::test]
async fn startup_authenticates_two_independent_creators_before_returning_ready_database() {
    let database = TestDatabase::create().await;
    let creators = stores(&database).await;
    creators
        .create(&credentials_for(creator(), SESSION, XPUB, 7, [9; 32]))
        .await
        .unwrap();
    creators
        .create(&credentials_for(
            other_creator(),
            "other-session",
            "other-xpub",
            19,
            [8; 32],
        ))
        .await
        .unwrap();

    let config = config_with_secrets("testnet", database.database_url(), MASTER_KEY);
    let ready_pool = initialize_database(&config).await.unwrap();
    let ready_crypto = Arc::new(Crypto::from_master_key(config.master_key().as_bytes()).unwrap());
    let ready_creators = CreatorStore::new(&ready_pool, ready_crypto.clone());
    let first = ready_creators.load(&creator()).await.unwrap();
    let second = ready_creators.load(&other_creator()).await.unwrap();
    assert_eq!(
        (
            first.bitcoin_account().unwrap().xpub.as_str(),
            first.bitcoin_account().unwrap().account_index
        ),
        (XPUB, 7)
    );
    assert_eq!(
        (
            second.bitcoin_account().unwrap().xpub.as_str(),
            second.bitcoin_account().unwrap().account_index
        ),
        ("other-xpub", 19)
    );
    ready_pool.close().await;
    database.cleanup().await;
}

#[tokio::test]
async fn exact_creator_id_lookup_is_isolated_and_never_falls_back() {
    let database = TestDatabase::create().await;
    let creators = stores(&database).await;
    let first = creators
        .create(&credentials_for(creator(), SESSION, XPUB, 7, [9; 32]))
        .await
        .unwrap();
    let second = creators
        .create(&credentials_for(
            other_creator(),
            OTHER_SESSION,
            OTHER_XPUB,
            19,
            [8; 32],
        ))
        .await
        .unwrap();

    let first_loaded = creators.load_by_id(first.id()).await.unwrap();
    let second_loaded = creators.load_by_id(second.id()).await.unwrap();
    assert_eq!(
        (
            first_loaded.creator(),
            first_loaded.bitcoin_account().unwrap().xpub.as_str()
        ),
        (&creator(), XPUB)
    );
    assert_eq!(
        (
            second_loaded.creator(),
            second_loaded.bitcoin_account().unwrap().xpub.as_str()
        ),
        (&other_creator(), OTHER_XPUB)
    );
    assert!(matches!(
        creators.load_by_id(uuid::Uuid::new_v4()).await,
        Err(PersistenceError::CorruptOrMissing)
    ));

    database.cleanup().await;
}

#[tokio::test]
async fn startup_rejects_a_correctly_shaped_wrong_master_key_without_exposing_state() {
    let database = TestDatabase::create().await;
    let creators = stores(&database).await;
    creators
        .create(&credentials(SESSION, XPUB, 7, [9; 32]))
        .await
        .unwrap();

    let config = config_with_secrets("testnet", database.database_url(), WRONG_MASTER_KEY);
    let error = initialize_database(&config).await.unwrap_err();
    assert_eq!(error.to_string(), "creator integrity check failed");
    assert_startup_error_is_redacted(&error, database.database_url());
    database.cleanup().await;
}

#[tokio::test]
async fn startup_rejects_corrupt_encrypted_payment_records_before_readiness() {
    let database = TestDatabase::create().await;
    let creators = stores(&database).await;
    creators
        .create(&credentials(SESSION, XPUB, 7, [9; 32]))
        .await
        .unwrap();
    let creator_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM creators")
        .fetch_one(database.pool())
        .await
        .unwrap();
    let invoice_id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO invoices
         (id, creator_id, reader_lookup_hash, bundle_lookup_hash,
          lock_resource_lookup_hash, payment_request_lookup_hash,
          invoice_envelope, payment_status,
          payment_record_envelope, bitcoin_address_lookup_hash,
           derivation_index_lookup_hash, invoice_created_at, proposal_expires_at,
           payment_deadline, proposal_acceptance_seconds, payment_window_seconds)
          VALUES ($1, $2, $3, $4, $5, $6, $7, 'undetected', $8, $9, $10,
                  NOW(), NOW() + INTERVAL '30 minutes', NOW() + INTERVAL '1 hour',
                  1800, 3600)",
    )
    .bind(invoice_id)
    .bind(creator_id)
    .bind(b"reader".as_slice())
    .bind(b"bundle".as_slice())
    .bind(b"lock-resource".as_slice())
    .bind(b"request".as_slice())
    .bind(b"delivery-intent-envelope".as_slice())
    .bind(b"corrupt-payment-envelope".as_slice())
    .bind(b"payment-address-hash".as_slice())
    .bind(b"derivation-index-hash".as_slice())
    .execute(database.pool())
    .await
    .unwrap();

    let config = config_with_secrets("testnet", database.database_url(), MASTER_KEY);
    let error = initialize_database(&config).await.unwrap_err();
    assert_eq!(error.to_string(), "payment record integrity check failed");
    assert_startup_error_is_redacted(&error, database.database_url());
    database.cleanup().await;
}

#[tokio::test]
async fn startup_rejects_one_corrupt_creator_before_returning_ready_database() {
    let database = TestDatabase::create().await;
    let creators = stores(&database).await;
    creators
        .create(&credentials(SESSION, XPUB, 7, [9; 32]))
        .await
        .unwrap();
    let invalid = creators
        .create(&credentials_for(
            other_creator(),
            "other-session",
            "other-xpub",
            19,
            [8; 32],
        ))
        .await
        .unwrap();
    sqlx::query("UPDATE creators SET credential_envelope = $1 WHERE id = $2")
        .bind(b"corrupt-creator-envelope".as_slice())
        .bind(invalid.id())
        .execute(database.pool())
        .await
        .unwrap();

    let config = config_with_secrets("testnet", database.database_url(), MASTER_KEY);
    let error = initialize_database(&config).await.unwrap_err();
    assert_eq!(error.to_string(), "creator integrity check failed");
    assert_startup_error_is_redacted(&error, database.database_url());
    database.cleanup().await;
}

#[tokio::test]
async fn startup_rejects_creator_envelopes_swapped_between_rows() {
    let database = TestDatabase::create().await;
    let creators = stores(&database).await;
    let first = creators
        .create(&credentials(SESSION, XPUB, 7, [9; 32]))
        .await
        .unwrap();
    let second = creators
        .create(&credentials_for(
            other_creator(),
            "other-session",
            "other-xpub",
            19,
            [8; 32],
        ))
        .await
        .unwrap();
    let first_envelope: Vec<u8> =
        sqlx::query_scalar("SELECT credential_envelope FROM creators WHERE id = $1")
            .bind(first.id())
            .fetch_one(database.pool())
            .await
            .unwrap();
    let second_envelope: Vec<u8> =
        sqlx::query_scalar("SELECT credential_envelope FROM creators WHERE id = $1")
            .bind(second.id())
            .fetch_one(database.pool())
            .await
            .unwrap();
    sqlx::query("UPDATE creators SET credential_envelope = $1 WHERE id = $2")
        .bind(second_envelope)
        .bind(first.id())
        .execute(database.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE creators SET credential_envelope = $1 WHERE id = $2")
        .bind(first_envelope)
        .bind(second.id())
        .execute(database.pool())
        .await
        .unwrap();

    let config = config_with_secrets("testnet", database.database_url(), MASTER_KEY);
    let error = initialize_database(&config).await.unwrap_err();
    assert_eq!(error.to_string(), "creator integrity check failed");
    assert_startup_error_is_redacted(&error, database.database_url());
    database.cleanup().await;
}

#[tokio::test]
async fn creator_setup_lock_serializes_publication_before_a_retry() {
    const NONE: usize = 0;
    const FAILED_FIRST: usize = 1;
    const WINNER: usize = 2;

    let database = TestDatabase::create().await;
    let creators = stores(&database).await;
    let publication = Arc::new(AtomicUsize::new(NONE));

    // A retry must wait until the previous publication attempt releases its lock.
    let failed_lock = creators.acquire_setup_lock(&creator()).await.unwrap();
    publication.store(FAILED_FIRST, Ordering::SeqCst);
    let winner_creators = creators.clone();
    let winner_publication = publication.clone();
    let winner = tokio::spawn(async move {
        let lock = winner_creators
            .acquire_setup_lock(&creator())
            .await
            .unwrap();
        winner_publication.store(WINNER, Ordering::SeqCst);
        lock.release().await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !winner.is_finished(),
        "winner setup acquired the creator lock before the previous setup released its lock"
    );

    failed_lock.release().await.unwrap();
    winner.await.unwrap();
    assert_eq!(publication.load(Ordering::SeqCst), WINNER);

    database.cleanup().await;
}

#[tokio::test]
async fn setup_locks_for_different_creators_do_not_block_each_other() {
    let database = TestDatabase::create().await;
    let creators = stores(&database).await;
    let first_lock = creators.acquire_setup_lock(&creator()).await.unwrap();

    let other_creators = creators.clone();
    let other_lock = tokio::time::timeout(Duration::from_secs(1), async move {
        other_creators.acquire_setup_lock(&other_creator()).await
    })
    .await
    .expect("another Creator setup must not wait for the first Creator lock")
    .unwrap();

    other_lock.release().await.unwrap();
    first_lock.release().await.unwrap();
    database.cleanup().await;
}

#[tokio::test]
async fn deployment_initialization_is_restart_safe_and_rejects_mismatches() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let store = DeploymentStore::new(database.pool());
    store
        .initialize(config("testnet").deployment_invariants())
        .await
        .unwrap();
    store
        .initialize(config("testnet").deployment_invariants())
        .await
        .unwrap();
    let mismatch = store
        .initialize(config("regtest").deployment_invariants())
        .await
        .unwrap_err();
    assert_eq!(
        mismatch.to_string(),
        "deployment metadata does not match configuration"
    );
    sqlx::query("UPDATE deployment_metadata SET paykit_client_id = 'other.paykit.server'")
        .execute(database.pool())
        .await
        .unwrap();
    let client_mismatch = store
        .initialize(config("testnet").deployment_invariants())
        .await
        .unwrap_err();
    assert_eq!(
        client_mismatch.to_string(),
        "deployment metadata does not match configuration"
    );
    sqlx::query("UPDATE deployment_metadata SET paykit_client_id = 'app.paykit.server'")
        .execute(database.pool())
        .await
        .unwrap();
    store
        .initialize(config("testnet").deployment_invariants())
        .await
        .unwrap();
    database.cleanup().await;
}

#[tokio::test]
async fn creator_authority_round_trips_only_through_ciphertext() {
    let database = TestDatabase::create().await;
    let creators = stores(&database).await;
    creators
        .create(&credentials(SESSION, XPUB, 7, [9; 32]))
        .await
        .unwrap();
    let loaded = creators.load(&creator()).await.unwrap();
    assert_eq!(loaded.session_secret(), SESSION);
    assert_eq!(loaded.bitcoin_account().unwrap().xpub.as_str(), XPUB);
    assert_eq!(loaded.bitcoin_account().unwrap().account_index, 7);
    assert_eq!(loaded.paykit_identity_secret().as_bytes(), &[9; 32]);
    let row = sqlx::query("SELECT credential_envelope FROM creators")
        .fetch_one(database.pool())
        .await
        .unwrap();
    let raw: Vec<u8> = row.get("credential_envelope");
    for secret in [
        SESSION.as_bytes(),
        XPUB.as_bytes(),
        CREATOR.as_bytes(),
        &[9; 32],
    ] {
        assert!(!raw.windows(secret.len()).any(|window| window == secret));
    }
    database.cleanup().await;
}

#[tokio::test]
async fn credential_scan_rejects_corruption_without_reading_business_history() {
    let database = TestDatabase::create().await;
    let creators = stores(&database).await;
    let persisted = creators
        .create(&credentials(SESSION, XPUB, 7, [9; 32]))
        .await
        .unwrap();
    sqlx::query("INSERT INTO invoices (creator_id, reader_lookup_hash, bundle_lookup_hash, lock_resource_lookup_hash, payment_request_lookup_hash, invoice_envelope, payment_record_envelope, bitcoin_address_lookup_hash, derivation_index_lookup_hash, payment_status, invoice_created_at, proposal_expires_at, payment_deadline, proposal_acceptance_seconds, payment_window_seconds) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW() + INTERVAL '30 minutes', NOW() + INTERVAL '1 hour', 1800, 3600)")
        .bind(persisted.id()).bind(b"poison-reader".as_slice()).bind(b"poison-bundle".as_slice()).bind(b"poison-lock-resource".as_slice()).bind(b"poison-request".as_slice()).bind(b"poison-invoice".as_slice()).bind(b"poison-payment-record".as_slice()).bind(b"poison-address-hash".as_slice()).bind(b"poison-index-hash".as_slice()).bind("undetected").execute(database.pool()).await.unwrap();
    sqlx::query("INSERT INTO outbox (creator_id, intent_envelope, intent_kind, status) VALUES ($1, $2, 'endpoint_publication', $3)")
        .bind(persisted.id())
        .bind(b"poison-outbox".as_slice())
        .bind("queued")
        .execute(database.pool())
        .await
        .unwrap();
    creators.scan_integrity().await.unwrap();
    sqlx::query("UPDATE creators SET credential_envelope = $1")
        .bind(b"corrupt".as_slice())
        .execute(database.pool())
        .await
        .unwrap();
    assert!(creators.scan_integrity().await.is_err());
    database.cleanup().await;
}

#[tokio::test]
async fn reauthentication_preserves_key_index_and_assignments_and_rejects_account_changes() {
    let database = TestDatabase::create().await;
    let creators = stores(&database).await;
    let persisted = creators
        .create(&credentials(SESSION, XPUB, 7, [9; 32]))
        .await
        .unwrap();
    sqlx::query("INSERT INTO reader_assignments (creator_id, reader_lookup_hash, bundle_lookup_hash, assignment_envelope) VALUES ($1, $2, $3, $4)")
        .bind(persisted.id()).bind(b"reader".as_slice()).bind(b"bundle".as_slice()).bind(b"assignment".as_slice()).execute(database.pool()).await.unwrap();
    creators
        .reauthenticate(&credentials("new-session", XPUB, 7, [9; 32]))
        .await
        .unwrap();
    let restored = creators.load(&creator()).await.unwrap();
    assert_eq!(restored.session_secret(), "new-session");
    assert_eq!(restored.paykit_identity_secret().as_bytes(), &[9; 32]);
    assert_eq!(restored.bitcoin_account().unwrap().account_index, 7);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM reader_assignments")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        1
    );
    assert!(
        creators
            .reauthenticate(&credentials("bad", "other-xpub", 7, [9; 32]))
            .await
            .is_err()
    );
    assert!(
        creators
            .reauthenticate(&credentials("bad", XPUB, 8, [9; 32]))
            .await
            .is_err()
    );
    assert_eq!(
        creators.load(&creator()).await.unwrap().session_secret(),
        "new-session"
    );
    database.cleanup().await;
}

#[tokio::test]
async fn reauthentication_requires_monotonic_key_generation_and_marks_setup_incomplete() {
    let database = TestDatabase::create().await;
    let creators = stores(&database).await;
    creators
        .create(&credentials(SESSION, XPUB, 7, [9; 32]))
        .await
        .unwrap();
    assert!(!creators.setup_complete(&creator()).await.unwrap());
    creators.mark_setup_complete(&creator()).await.unwrap();
    assert!(creators.setup_complete(&creator()).await.unwrap());
    assert!(
        creators
            .reauthenticate(&credentials("substitution", XPUB, 7, [8; 32]))
            .await
            .is_err()
    );
    let rotated = CreatorCredentials::new(
        creator(),
        "rotated-session".into(),
        PaykitIdentitySecretKey::new([8; 32], 2).unwrap(),
        Some(paykit_server::domain::receiving::BitcoinAccount {
            xpub: XPUB.to_owned().into(),
            account_index: 7,
        }),
        None,
    );
    creators.reauthenticate(&rotated).await.unwrap();
    assert!(!creators.setup_complete(&creator()).await.unwrap());
    assert_eq!(
        creators
            .load(&creator())
            .await
            .unwrap()
            .paykit_identity_secret()
            .key_generation(),
        2
    );
    assert!(
        creators
            .reauthenticate(&credentials("rollback", XPUB, 7, [9; 32]))
            .await
            .is_err()
    );
    assert_eq!(
        creators.load(&creator()).await.unwrap().session_secret(),
        "rotated-session"
    );
    database.cleanup().await;
}

#[tokio::test]
async fn reauthentication_can_add_but_cannot_replace_approved_usdt_details() {
    use paykit_server::domain::receiving::UsdtAddress;
    let database = TestDatabase::create().await;
    let creators = stores(&database).await;
    let original = credentials(SESSION, XPUB, 7, [9; 32]);
    creators.create(&original).await.unwrap();
    let address =
        UsdtAddress::try_from("0x2222222222222222222222222222222222222222".to_owned()).unwrap();
    let updated = CreatorCredentials::new(
        creator(),
        "new-session".into(),
        PaykitIdentitySecretKey::new([9; 32], 1).unwrap(),
        original.bitcoin_account().cloned(),
        Some(address.clone()),
    );
    creators.reauthenticate(&updated).await.unwrap();
    assert_eq!(
        creators.load(&creator()).await.unwrap().usdt_address(),
        Some(&address)
    );
    let replacement = CreatorCredentials::new(
        creator(),
        "bad".into(),
        PaykitIdentitySecretKey::new([9; 32], 1).unwrap(),
        original.bitcoin_account().cloned(),
        Some(
            UsdtAddress::try_from("0x3333333333333333333333333333333333333333".to_owned()).unwrap(),
        ),
    );
    assert!(creators.reauthenticate(&replacement).await.is_err());
    assert!(creators.reauthenticate(&original).await.is_err());
    assert_eq!(
        creators.load(&creator()).await.unwrap().usdt_address(),
        Some(&address)
    );
    database.cleanup().await;
}
