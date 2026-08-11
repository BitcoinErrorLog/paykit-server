use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use paykit_sdk::{ReceiverNoiseSecretKey, storage::StorageState};
use paykit_server::{
    config::{Config, ConfigEnvironment},
    crypto::Crypto,
    domain::locks::parse_creator,
    persistence::{
        CreatorCredentials, CreatorStore, DeploymentStore, PersistenceError, SdkStateStore,
        run_migrations,
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
receiver_path = "paykit/server"
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
        ReceiverNoiseSecretKey::new(noise),
        xpub.to_owned(),
        index,
    )
}
fn credentials(session: &str, xpub: &str, index: u32, noise: [u8; 32]) -> CreatorCredentials {
    credentials_for(creator(), session, xpub, index, noise)
}

async fn stores(database: &TestDatabase) -> (CreatorStore, SdkStateStore) {
    run_migrations(database.pool()).await.unwrap();
    let crypto = crypto();
    (
        CreatorStore::new(database.pool(), crypto.clone()),
        SdkStateStore::new(database.pool(), crypto),
    )
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
    let (creators, _) = stores(&database).await;
    let first_state = StorageState {
        next_outbound_private_message_id: 11,
        ..StorageState::default()
    };
    let second_state = StorageState {
        next_receive_batch_id: 22,
        ..StorageState::default()
    };
    creators
        .create(
            &credentials_for(creator(), SESSION, XPUB, 7, [9; 32]),
            &first_state,
        )
        .await
        .unwrap();
    creators
        .create(
            &credentials_for(other_creator(), "other-session", "other-xpub", 19, [8; 32]),
            &second_state,
        )
        .await
        .unwrap();

    let config = config_with_secrets("testnet", database.database_url(), MASTER_KEY);
    let ready_pool = initialize_database(&config).await.unwrap();
    let ready_crypto = Arc::new(Crypto::from_master_key(config.master_key().as_bytes()).unwrap());
    let ready_creators = CreatorStore::new(&ready_pool, ready_crypto.clone());
    let ready_states = SdkStateStore::new(&ready_pool, ready_crypto);
    let first = ready_creators.load(&creator()).await.unwrap();
    let second = ready_creators.load(&other_creator()).await.unwrap();
    assert_eq!((first.xpub(), first.account_index()), (XPUB, 7));
    assert_eq!((second.xpub(), second.account_index()), ("other-xpub", 19));
    assert_eq!(ready_states.load(&creator()).await.unwrap(), first_state);
    assert_eq!(
        ready_states.load(&other_creator()).await.unwrap(),
        second_state
    );
    ready_pool.close().await;
    database.cleanup().await;
}

#[tokio::test]
async fn exact_creator_id_lookup_is_isolated_and_never_falls_back() {
    let database = TestDatabase::create().await;
    let (creators, _) = stores(&database).await;
    let first = creators
        .create(
            &credentials_for(creator(), SESSION, XPUB, 7, [9; 32]),
            &StorageState::default(),
        )
        .await
        .unwrap();
    let second = creators
        .create(
            &credentials_for(other_creator(), OTHER_SESSION, OTHER_XPUB, 19, [8; 32]),
            &StorageState::default(),
        )
        .await
        .unwrap();

    let first_loaded = creators.load_by_id(first.id()).await.unwrap();
    let second_loaded = creators.load_by_id(second.id()).await.unwrap();
    assert_eq!(
        (first_loaded.creator(), first_loaded.xpub()),
        (&creator(), XPUB)
    );
    assert_eq!(
        (second_loaded.creator(), second_loaded.xpub()),
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
    let (creators, _) = stores(&database).await;
    creators
        .create(
            &credentials(SESSION, XPUB, 7, [9; 32]),
            &StorageState::default(),
        )
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
    let (creators, _) = stores(&database).await;
    creators
        .create(
            &credentials(SESSION, XPUB, 7, [9; 32]),
            &StorageState::default(),
        )
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
          payment_request_lookup_hash, invoice_envelope, payment_status,
          payment_record_envelope, bitcoin_address_lookup_hash,
           derivation_index_lookup_hash, invoice_created_at, payment_deadline,
           payment_in_hours)
          VALUES ($1, $2, $3, $4, $5, $6, 'undetected', $7, $8, $9,
                  NOW(), NOW() + INTERVAL '1 hour', 1)",
    )
    .bind(invoice_id)
    .bind(creator_id)
    .bind(b"reader".as_slice())
    .bind(b"bundle".as_slice())
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
async fn startup_rejects_one_corrupt_creator_or_sdk_state_before_returning_ready_database() {
    for corrupt_sdk_state in [false, true] {
        let database = TestDatabase::create().await;
        let (creators, _) = stores(&database).await;
        creators
            .create(
                &credentials(SESSION, XPUB, 7, [9; 32]),
                &StorageState::default(),
            )
            .await
            .unwrap();
        let invalid = creators
            .create(
                &credentials_for(other_creator(), "other-session", "other-xpub", 19, [8; 32]),
                &StorageState::default(),
            )
            .await
            .unwrap();
        if corrupt_sdk_state {
            sqlx::query("UPDATE sdk_states SET state_envelope = $1 WHERE creator_id = $2")
                .bind(b"corrupt-sdk-state".as_slice())
                .bind(invalid.id())
                .execute(database.pool())
                .await
                .unwrap();
        } else {
            sqlx::query("UPDATE creators SET credential_envelope = $1 WHERE id = $2")
                .bind(b"corrupt-creator-envelope".as_slice())
                .bind(invalid.id())
                .execute(database.pool())
                .await
                .unwrap();
        }

        let config = config_with_secrets("testnet", database.database_url(), MASTER_KEY);
        let error = initialize_database(&config).await.unwrap_err();
        assert_eq!(error.to_string(), "creator integrity check failed");
        assert_startup_error_is_redacted(&error, database.database_url());
        database.cleanup().await;
    }
}

#[tokio::test]
async fn startup_rejects_creator_envelopes_swapped_between_rows() {
    let database = TestDatabase::create().await;
    let (creators, _) = stores(&database).await;
    let first = creators
        .create(
            &credentials(SESSION, XPUB, 7, [9; 32]),
            &StorageState::default(),
        )
        .await
        .unwrap();
    let second = creators
        .create(
            &credentials_for(other_creator(), "other-session", "other-xpub", 19, [8; 32]),
            &StorageState::default(),
        )
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
async fn creator_setup_lock_serializes_failed_first_setup_compensation_before_winner_publication() {
    const NONE: usize = 0;
    const FAILED_FIRST: usize = 1;
    const WINNER: usize = 2;

    let database = TestDatabase::create().await;
    let (creators, _) = stores(&database).await;
    let marker = Arc::new(AtomicUsize::new(NONE));

    // The failed first setup owns the creator lock from its initial lookup
    // through marker compensation. A competing first setup cannot publish a
    // winner marker until after that compensation has completed.
    let failed_lock = creators.acquire_setup_lock(&creator()).await.unwrap();
    marker.store(FAILED_FIRST, Ordering::SeqCst);
    let winner_creators = creators.clone();
    let winner_marker = marker.clone();
    let winner = tokio::spawn(async move {
        let lock = winner_creators
            .acquire_setup_lock(&creator())
            .await
            .unwrap();
        winner_marker.store(WINNER, Ordering::SeqCst);
        lock.release().await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !winner.is_finished(),
        "winner setup acquired the creator lock before failed setup compensated"
    );

    marker.store(NONE, Ordering::SeqCst); // failed first setup compensation
    failed_lock.release().await.unwrap();
    winner.await.unwrap();
    assert_eq!(marker.load(Ordering::SeqCst), WINNER);

    database.cleanup().await;
}

#[tokio::test]
async fn setup_locks_for_different_creators_do_not_block_each_other() {
    let database = TestDatabase::create().await;
    let (creators, _) = stores(&database).await;
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
async fn setup_and_sdk_mutation_for_one_creator_leave_all_other_creator_state_unchanged() {
    let database = TestDatabase::create().await;
    let (creators, states) = stores(&database).await;
    let first_state = StorageState {
        next_outbound_private_message_id: 11,
        ..StorageState::default()
    };
    let second_state = StorageState {
        next_receive_batch_id: 22,
        ..StorageState::default()
    };
    let first = creators
        .create(
            &credentials_for(creator(), SESSION, XPUB, 7, [9; 32]),
            &first_state,
        )
        .await
        .unwrap();
    let second = creators
        .create(
            &credentials_for(other_creator(), OTHER_SESSION, OTHER_XPUB, 19, [8; 32]),
            &second_state,
        )
        .await
        .unwrap();
    sqlx::query("UPDATE creators SET next_child_index = 31 WHERE id = $1")
        .bind(first.id())
        .execute(database.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE creators SET next_child_index = 47 WHERE id = $1")
        .bind(second.id())
        .execute(database.pool())
        .await
        .unwrap();

    creators
        .reauthenticate(&credentials_for(
            creator(),
            "first-new-session",
            XPUB,
            7,
            [4; 32],
        ))
        .await
        .unwrap();
    states
        .update(&creator(), |state| {
            state.next_outbound_private_message_id += 1;
        })
        .await
        .unwrap();

    let first_credentials = creators.load(&creator()).await.unwrap();
    let other_credentials = creators.load(&other_creator()).await.unwrap();
    assert_eq!(first_credentials.session_secret(), "first-new-session");
    assert_eq!(
        first_credentials.receiver_noise_secret().as_bytes(),
        &[9; 32]
    );
    assert_eq!(
        (first_credentials.xpub(), first_credentials.account_index()),
        (XPUB, 7)
    );
    assert_eq!(other_credentials.session_secret(), OTHER_SESSION);
    assert_eq!(
        other_credentials.receiver_noise_secret().as_bytes(),
        &[8; 32]
    );
    assert_eq!(
        (other_credentials.xpub(), other_credentials.account_index()),
        (OTHER_XPUB, 19)
    );
    assert_eq!(
        states
            .load(&creator())
            .await
            .unwrap()
            .next_outbound_private_message_id,
        12
    );
    assert_eq!(states.load(&other_creator()).await.unwrap(), second_state);
    let first_derivation: i64 =
        sqlx::query_scalar("SELECT next_child_index FROM creators WHERE id = $1")
            .bind(first.id())
            .fetch_one(database.pool())
            .await
            .unwrap();
    let other_derivation: i64 =
        sqlx::query_scalar("SELECT next_child_index FROM creators WHERE id = $1")
            .bind(second.id())
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(first_derivation, 31);
    assert_eq!(other_derivation, 47);

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
    store
        .initialize(config("testnet").deployment_invariants())
        .await
        .unwrap();
    database.cleanup().await;
}

#[tokio::test]
async fn creator_and_sdk_state_round_trip_only_through_ciphertext() {
    let database = TestDatabase::create().await;
    let (creators, states) = stores(&database).await;
    let initial = StorageState {
        next_outbound_private_message_id: 41,
        ..StorageState::default()
    };
    creators
        .create(&credentials(SESSION, XPUB, 7, [9; 32]), &initial)
        .await
        .unwrap();
    let loaded = creators.load(&creator()).await.unwrap();
    assert_eq!(loaded.session_secret(), SESSION);
    assert_eq!(loaded.xpub(), XPUB);
    assert_eq!(loaded.account_index(), 7);
    assert_eq!(loaded.receiver_noise_secret().as_bytes(), &[9; 32]);
    assert_eq!(states.load(&creator()).await.unwrap(), initial);
    let row = sqlx::query("SELECT credential_envelope, state_envelope FROM creators JOIN sdk_states ON sdk_states.creator_id = creators.id")
        .fetch_one(database.pool()).await.unwrap();
    let raw: Vec<u8> = row.get("credential_envelope");
    let state: Vec<u8> = row.get("state_envelope");
    for secret in [
        SESSION.as_bytes(),
        XPUB.as_bytes(),
        CREATOR.as_bytes(),
        &[9; 32],
    ] {
        assert!(!raw.windows(secret.len()).any(|window| window == secret));
        assert!(!state.windows(secret.len()).any(|window| window == secret));
    }
    database.cleanup().await;
}

#[tokio::test]
async fn creator_create_rolls_back_when_initial_sdk_state_insert_fails() {
    let database = TestDatabase::create().await;
    let (creators, _) = stores(&database).await;
    sqlx::query(
        "CREATE FUNCTION fail_initial_sdk_state_insert() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN RAISE EXCEPTION 'forced sdk state insert failure'; END; $$",
    )
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER fail_initial_sdk_state_insert \
         BEFORE INSERT ON sdk_states FOR EACH ROW \
         EXECUTE FUNCTION fail_initial_sdk_state_insert()",
    )
    .execute(database.pool())
    .await
    .unwrap();

    assert!(
        creators
            .create(
                &credentials(SESSION, XPUB, 7, [9; 32]),
                &StorageState::default(),
            )
            .await
            .is_err()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM creators")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        0
    );
    database.cleanup().await;
}

#[tokio::test]
async fn boot_scan_rejects_corrupt_creator_sdk_and_missing_state_without_historical_reads() {
    let database = TestDatabase::create().await;
    let (creators, _) = stores(&database).await;
    let persisted = creators
        .create(
            &credentials(SESSION, XPUB, 7, [9; 32]),
            &StorageState::default(),
        )
        .await
        .unwrap();
    sqlx::query("INSERT INTO invoices (creator_id, reader_lookup_hash, bundle_lookup_hash, payment_request_lookup_hash, invoice_envelope, payment_record_envelope, bitcoin_address_lookup_hash, derivation_index_lookup_hash, payment_status, invoice_created_at, payment_deadline, payment_in_hours) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW() + INTERVAL '1 hour', 1)")
        .bind(persisted.id()).bind(b"poison-reader".as_slice()).bind(b"poison-bundle".as_slice()).bind(b"poison-request".as_slice()).bind(b"poison-invoice".as_slice()).bind(b"poison-payment-record".as_slice()).bind(b"poison-address-hash".as_slice()).bind(b"poison-index-hash".as_slice()).bind("undetected").execute(database.pool()).await.unwrap();
    sqlx::query("INSERT INTO outbox (creator_id, intent_envelope, status) VALUES ($1, $2, $3)")
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
async fn boot_scan_rejects_corrupt_sdk_state_and_missing_sdk_state() {
    let database = TestDatabase::create().await;
    let (creators, _) = stores(&database).await;
    let persisted = creators
        .create(
            &credentials(SESSION, XPUB, 7, [9; 32]),
            &StorageState::default(),
        )
        .await
        .unwrap();
    sqlx::query("UPDATE sdk_states SET state_envelope = $1 WHERE creator_id = $2")
        .bind(b"corrupt-sdk-state".as_slice())
        .bind(persisted.id())
        .execute(database.pool())
        .await
        .unwrap();
    assert!(creators.scan_integrity().await.is_err());
    sqlx::query("DELETE FROM sdk_states WHERE creator_id = $1")
        .bind(persisted.id())
        .execute(database.pool())
        .await
        .unwrap();
    assert!(creators.scan_integrity().await.is_err());
    database.cleanup().await;
}

#[tokio::test]
async fn reauthentication_preserves_noise_index_and_assignments_and_rejects_account_changes() {
    let database = TestDatabase::create().await;
    let (creators, _) = stores(&database).await;
    let persisted = creators
        .create(
            &credentials(SESSION, XPUB, 7, [9; 32]),
            &StorageState::default(),
        )
        .await
        .unwrap();
    sqlx::query("INSERT INTO reader_assignments (creator_id, reader_lookup_hash, bundle_lookup_hash, assignment_envelope) VALUES ($1, $2, $3, $4)")
        .bind(persisted.id()).bind(b"reader".as_slice()).bind(b"bundle".as_slice()).bind(b"assignment".as_slice()).execute(database.pool()).await.unwrap();
    creators
        .reauthenticate(&credentials("new-session", XPUB, 7, [4; 32]))
        .await
        .unwrap();
    let restored = creators.load(&creator()).await.unwrap();
    assert_eq!(restored.session_secret(), "new-session");
    assert_eq!(restored.receiver_noise_secret().as_bytes(), &[9; 32]);
    assert_eq!(restored.account_index(), 7);
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
async fn concurrent_sdk_updates_serialize_and_retain_both_mutations() {
    let database = TestDatabase::create().await;
    let (creators, states) = stores(&database).await;
    creators
        .create(
            &credentials(SESSION, XPUB, 7, [9; 32]),
            &StorageState::default(),
        )
        .await
        .unwrap();
    let first = states.clone();
    let second = states.clone();
    let creator_one = creator();
    let creator_two = creator();
    let (one, two) = tokio::join!(
        first.update(&creator_one, |state| state
            .next_outbound_private_message_id +=
            1),
        second.update(&creator_two, |state| state.next_receive_batch_id += 1),
    );
    one.unwrap();
    two.unwrap();
    let state = states.load(&creator()).await.unwrap();
    assert_eq!(state.next_outbound_private_message_id, 1);
    assert_eq!(state.next_receive_batch_id, 1);
    database.cleanup().await;
}
