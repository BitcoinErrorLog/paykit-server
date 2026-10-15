use std::sync::Arc;

use async_trait::async_trait;
use paykit_sdk::PaykitIdentitySecretKey;
use paykit_server::{
    application::{
        create_invoice::{
            AppRegistryDiscovery, CreatorReceivingProvider, ReaderAuthorization,
            RegistryDiscoveryError, SessionValidationError, SessionValidator,
        },
        marketplace_preparation::{
            PrepareMarketplaceError, PrepareMarketplaceRequest, PrepareMarketplaceService,
        },
        semantic_intent::DeliveryIntentV1,
    },
    config::BitcoinNetwork,
    crypto::{Crypto, EncryptedEnvelope, EnvelopeContext},
    domain::{
        invoice::CriterionAsset,
        locks::{CreatorPubky, ReaderPubky, parse_creator, parse_reader},
    },
    persistence::{
        CreatorCredentials, CreatorStore, MarketplaceActivationInput,
        MarketplaceLifecyclePersistenceError, MarketplacePreparationInput,
        MarketplacePreparationPayloadFactory, MarketplacePreparationPayloads,
        MarketplacePreparationStore, MarketplaceResolutionOutcome, OutboxStore, PersistenceError,
        run_migrations,
    },
};
use paykit_server_e2e::postgres::TestDatabase;
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

mod common;

const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";

type MarketplaceLifecycleFacts = (
    uuid::Uuid,
    String,
    Option<OffsetDateTime>,
    Option<OffsetDateTime>,
    Option<OffsetDateTime>,
);

fn creator() -> CreatorPubky {
    parse_creator(CREATOR).unwrap()
}

fn other_creator() -> CreatorPubky {
    for replacement in "ybndrfg8ejkmcpqxot1uwisza345h769".chars() {
        let mut candidate = CREATOR.to_owned();
        candidate.replace_range(6..7, &replacement.to_string());
        if let Ok(parsed) = parse_creator(&candidate)
            && parsed != creator()
        {
            return parsed;
        }
    }
    panic!("valid second creator fixture")
}

fn reader() -> ReaderPubky {
    for replacement in "ybndrfg8ejkmcpqxot1uwisza345h769".chars() {
        let mut candidate = CREATOR.to_owned();
        candidate.replace_range(5..6, &replacement.to_string());
        if let Ok(reader) = parse_reader(&candidate) {
            return reader;
        }
    }
    panic!("valid reader fixture")
}

fn crypto() -> Arc<Crypto> {
    Arc::new(Crypto::from_master_key(&[7; 32]).unwrap())
}

struct ReadySession;

#[async_trait]
impl SessionValidator for ReadySession {
    async fn validate(&self, _creator: &CreatorPubky) -> Result<(), SessionValidationError> {
        Ok(())
    }
}

struct ReadyRegistry;

#[async_trait]
impl AppRegistryDiscovery for ReadyRegistry {
    async fn discover(
        &self,
        _reader: &ReaderPubky,
    ) -> Result<Option<paykit_lib::PaykitAppRegistry>, RegistryDiscoveryError> {
        let mut registry = paykit_lib::PaykitAppRegistry::new(Some(
            paykit_lib::derive_paykit_noise_public_key(&[8; 32]),
        ));
        registry
            .register_app(
                paykit_lib::PaykitAppId::new("bitkit").unwrap(),
                paykit_lib::PaykitApp::new(
                    "Bitkit",
                    paykit_lib::PaykitAppCapabilities {
                        private_payments: false,
                        payment_requests: true,
                        receipts: false,
                        outgoing_payments: true,
                    },
                )
                .unwrap(),
            )
            .unwrap();
        Ok(Some(registry))
    }

    async fn authorization(
        &self,
        _reader: &ReaderPubky,
    ) -> Result<ReaderAuthorization, RegistryDiscoveryError> {
        Ok(ReaderAuthorization::Verified)
    }
}

fn account_xpub() -> String {
    use bitcoin::{
        Network,
        bip32::{ChildNumber, Xpriv, Xpub},
        secp256k1::Secp256k1,
    };
    let secp = Secp256k1::new();
    let account = Xpriv::new_master(Network::Bitcoin, &[42; 32])
        .unwrap()
        .derive_priv(
            &secp,
            &[
                ChildNumber::from_hardened_idx(84).unwrap(),
                ChildNumber::from_hardened_idx(0).unwrap(),
                ChildNumber::from_hardened_idx(0).unwrap(),
            ],
        )
        .unwrap();
    Xpub::from_priv(&secp, &account).to_string()
}

fn parse_rfc3339(value: &str) -> OffsetDateTime {
    OffsetDateTime::parse(value, &Rfc3339).unwrap()
}

#[test]
fn rfc3339_timestamp_equality_preserves_fractional_instants() {
    let expected = parse_rfc3339("2026-10-11T12:00:00.86877Z");

    assert_eq!(parse_rfc3339("2026-10-11T12:00:00.868770Z"), expected);
    assert_ne!(parse_rfc3339("2026-10-11T12:00:00.868771Z"), expected);
}

struct Payloads;

struct DescribedPayloads {
    note: Option<&'static str>,
}

#[derive(Serialize, Deserialize)]
struct StoredPreparationEnvelope {
    version: u8,
    operation_id: String,
    request_binding: Vec<u8>,
    reader: String,
    reference: String,
    terms: paykit_server::application::marketplace_terms::MarketplaceTerms,
    payment_window_seconds: u64,
    prepare_ttl_seconds: u64,
    prepared_at: OffsetDateTime,
    prepare_expires_at: OffsetDateTime,
    child_index: i64,
    payment_request_intent: DeliveryIntentV1,
}

impl MarketplacePreparationPayloadFactory for Payloads {
    fn for_child_index(
        &self,
        child_index: i64,
    ) -> Result<MarketplacePreparationPayloads, PersistenceError> {
        Ok(MarketplacePreparationPayloads {
            payment_request_intent: common::payment_intent_with_reference(
                &reader(),
                format!("marketplace-address-{child_index}"),
                "7cceb26d-9042-4ea6-bfcb-01bbd778d76e".into(),
            ),
        })
    }
}

impl MarketplacePreparationPayloadFactory for DescribedPayloads {
    fn for_child_index(
        &self,
        child_index: i64,
    ) -> Result<MarketplacePreparationPayloads, PersistenceError> {
        Ok(MarketplacePreparationPayloads {
            payment_request_intent: common::payment_intent_with_reference_and_note(
                &reader(),
                format!("marketplace-address-{child_index}"),
                "7cceb26d-9042-4ea6-bfcb-01bbd778d76e".into(),
                self.note,
            ),
        })
    }
}

async fn store(database: &TestDatabase) -> MarketplacePreparationStore {
    run_migrations(database.pool()).await.unwrap();
    create_creator(database, creator(), "session-secret", 9).await;
    MarketplacePreparationStore::new(database.pool(), crypto())
}

async fn create_creator(
    database: &TestDatabase,
    creator: CreatorPubky,
    session_secret: &str,
    key_byte: u8,
) {
    CreatorStore::new(database.pool(), crypto())
        .create(&CreatorCredentials::new(
            creator,
            session_secret.into(),
            PaykitIdentitySecretKey::new([key_byte; 32], 1).unwrap(),
            Some(paykit_server::domain::receiving::BitcoinAccount {
                xpub: account_xpub().into(),
                account_index: 0,
            }),
            None,
        ))
        .await
        .unwrap();
}

async fn preparation_service(database: &TestDatabase) -> PrepareMarketplaceService {
    let store = Arc::new(store(database).await);
    let credentials: Arc<dyn CreatorReceivingProvider> =
        Arc::new(CreatorStore::new(database.pool(), crypto()));
    PrepareMarketplaceService::new(
        Arc::new(ReadySession),
        Arc::new(ReadyRegistry),
        credentials,
        store,
        paykit_lib::PaykitAppId::new("paykit-server").unwrap(),
        BitcoinNetwork::Mainnet,
        std::time::Duration::from_secs(24 * 60 * 60),
        std::time::Duration::from_secs(15 * 60),
    )
}

fn application_request(description: String, operation_id: &str) -> PrepareMarketplaceRequest {
    PrepareMarketplaceRequest {
        creator: creator(),
        reader: reader(),
        reference: "7cceb26d-9042-4ea6-bfcb-01bbd778d76e".into(),
        amount: 100,
        asset: CriterionAsset::Btc,
        accepted_assets: None,
        operation_id: operation_id.into(),
        payment_window_seconds: 24 * 60 * 60,
        description: Some(description),
    }
}

#[tokio::test]
async fn final_frame_capacity_is_checked_before_preparation_persists() {
    let database = TestDatabase::create().await;
    let service = preparation_service(&database).await;

    assert_eq!(
        service
            .prepare(application_request(
                "🛒".repeat(83),
                "marketplace-payment:deadline-overflow:attempt-1",
            ))
            .await,
        Err(PrepareMarketplaceError::InvalidRequest)
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM marketplace_payment_preparations")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT next_child_index FROM creators")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        0
    );

    let prepared = service
        .prepare(application_request(
            "🛒".repeat(82),
            "marketplace-payment:deadline-fit:attempt-1",
        ))
        .await
        .unwrap();
    let creator = creator();
    let stored = stored_preparation_envelope(&database, &creator, prepared.invoice_id()).await;
    let stored_terms = stored.payment_request_intent.terms().unwrap();
    assert!(stored_terms.proposal_expires_at.is_none());
    assert!(stored_terms.payment_deadline.is_none());
    let activated = MarketplacePreparationStore::new(database.pool(), crypto())
        .activate(MarketplaceActivationInput {
            creator: &creator,
            invoice_id: prepared.invoice_id(),
            amount: 100,
            asset: CriterionAsset::Btc,
            proposal_acceptance_window: std::time::Duration::from_nanos(999_999_999),
        })
        .await
        .unwrap();
    assert!(activated.is_some());

    database.cleanup().await;
}

async fn wait_for_lock_waiters(database: &TestDatabase, minimum: i64) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_stat_activity
                 WHERE datname = current_database() AND wait_event_type = 'Lock'",
            )
            .fetch_one(database.pool())
            .await
            .unwrap();
            if waiting >= minimum {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("expected at least {minimum} PostgreSQL lock waiters"));
}

fn input<'a>(
    creator: &'a CreatorPubky,
    reader: &'a ReaderPubky,
    operation_id: &'a str,
    request_binding: &'a [u8],
) -> MarketplacePreparationInput<'a> {
    input_with_ttl(creator, reader, operation_id, request_binding, 15 * 60)
}

fn input_with_ttl<'a>(
    creator: &'a CreatorPubky,
    reader: &'a ReaderPubky,
    operation_id: &'a str,
    request_binding: &'a [u8],
    prepare_ttl_seconds: u64,
) -> MarketplacePreparationInput<'a> {
    input_with_ttl_and_window(
        creator,
        reader,
        operation_id,
        request_binding,
        prepare_ttl_seconds,
        24 * 60 * 60,
    )
}

fn input_with_ttl_and_window<'a>(
    creator: &'a CreatorPubky,
    reader: &'a ReaderPubky,
    operation_id: &'a str,
    request_binding: &'a [u8],
    prepare_ttl_seconds: u64,
    payment_window_seconds: u64,
) -> MarketplacePreparationInput<'a> {
    MarketplacePreparationInput {
        creator,
        reader,
        reference: "7cceb26d-9042-4ea6-bfcb-01bbd778d76e",
        operation_id,
        request_binding,
        amount: 100,
        asset: CriterionAsset::Btc,
        payment_window_seconds,
        prepare_ttl_seconds,
        prepare_deadline: common::deadline_after(prepare_ttl_seconds),
        payloads: &Payloads,
    }
}

fn input_with_payloads<'a>(
    creator: &'a CreatorPubky,
    reader: &'a ReaderPubky,
    operation_id: &'a str,
    request_binding: &'a [u8],
    payloads: &'a dyn MarketplacePreparationPayloadFactory,
) -> MarketplacePreparationInput<'a> {
    MarketplacePreparationInput {
        payloads,
        ..input(creator, reader, operation_id, request_binding)
    }
}

async fn stored_preparation_envelope(
    database: &TestDatabase,
    creator: &CreatorPubky,
    invoice_id: uuid::Uuid,
) -> StoredPreparationEnvelope {
    let encrypted: Vec<u8> = sqlx::query_scalar(
        "SELECT preparation_envelope FROM marketplace_payment_preparations WHERE id = $1",
    )
    .bind(invoice_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    let crypto = crypto();
    let context = EnvelopeContext::marketplace_preparation(
        crypto.lookup_hash(creator.to_string().as_bytes()),
        invoice_id,
    );
    let plaintext = crypto
        .decrypt(&context, &EncryptedEnvelope::from_bytes(encrypted))
        .unwrap();
    postcard::from_bytes(&plaintext).unwrap()
}

#[tokio::test]
async fn description_note_is_persisted_exactly_and_replay_keeps_original_intent() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let creator = creator();
    let reader = reader();
    let described = DescribedPayloads {
        note: Some("Café order 🛒"),
    };
    let omitted = DescribedPayloads { note: None };

    let first = store
        .prepare(input_with_payloads(
            &creator,
            &reader,
            "marketplace-payment:description:attempt-1",
            b"described-request",
            &described,
        ))
        .await
        .unwrap();
    let stored = stored_preparation_envelope(&database, &creator, first.invoice_id()).await;
    assert_eq!(
        stored.payment_request_intent.terms().unwrap().metadata,
        serde_json::Map::from_iter([(
            "note".into(),
            serde_json::Value::String("Café order 🛒".into()),
        )])
    );

    let replay = store
        .prepare(input_with_payloads(
            &creator,
            &reader,
            "marketplace-payment:description:attempt-1",
            b"described-request",
            &omitted,
        ))
        .await
        .unwrap();
    assert!(replay.replayed());
    assert_eq!(replay.invoice_id(), first.invoice_id());
    let replayed = stored_preparation_envelope(&database, &creator, replay.invoice_id()).await;
    assert_eq!(
        replayed.payment_request_intent,
        stored.payment_request_intent
    );

    let legacy = store
        .prepare(input_with_payloads(
            &creator,
            &reader,
            "marketplace-payment:description:attempt-2",
            b"legacy-request",
            &omitted,
        ))
        .await
        .unwrap();
    let legacy = stored_preparation_envelope(&database, &creator, legacy.invoice_id()).await;
    assert!(
        legacy
            .payment_request_intent
            .terms()
            .unwrap()
            .metadata
            .is_empty()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM marketplace_payment_preparations")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        2
    );

    database.cleanup().await;
}

#[tokio::test]
async fn preparation_is_durable_unpublished_and_replay_first() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let creator = creator();
    let reader = reader();

    let first = store
        .prepare(input_with_ttl(
            &creator,
            &reader,
            "marketplace-payment:order-1:attempt-1",
            b"request-one",
            1,
        ))
        .await
        .unwrap();
    assert!(!first.replayed());
    assert_eq!(first.terms().amount(), 100);
    assert_eq!(
        first.prepare_expires_at() - first.prepared_at(),
        time::Duration::seconds(1)
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM marketplace_payment_preparations")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM invoices")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM outbox")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM marketplace_settlements")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        0,
        "prepared work must not have settlement ownership"
    );

    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    let replay = store
        .prepare(input(
            &creator,
            &reader,
            "marketplace-payment:order-1:attempt-1",
            b"request-one",
        ))
        .await
        .unwrap();
    assert!(replay.replayed());
    assert_eq!(replay.invoice_id(), first.invoice_id());
    assert_eq!(replay.terms(), first.terms());
    assert_eq!(replay.quote(), first.quote());
    assert!(replay.prepare_expires_at() < time::OffsetDateTime::now_utc());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT next_child_index FROM creators")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        1,
        "exact replay allocated another address"
    );

    assert_eq!(
        store
            .prepare(input(
                &creator,
                &reader,
                "marketplace-payment:order-1:attempt-1",
                b"changed-request",
            ))
            .await,
        Err(PersistenceError::Conflict)
    );
    let second = store
        .prepare(input(
            &creator,
            &reader,
            "marketplace-payment:order-1:attempt-2",
            b"changed-request",
        ))
        .await
        .unwrap();
    assert_ne!(second.invoice_id(), first.invoice_id());
    assert_eq!(
        second.prepare_expires_at() - second.prepared_at(),
        time::Duration::minutes(15)
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM marketplace_payment_preparations")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM outbox")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        0
    );

    sqlx::query(
        "UPDATE marketplace_payment_preparations
         SET prepare_expires_at = prepare_expires_at + INTERVAL '1 second'
         WHERE id = $1",
    )
    .bind(first.invoice_id())
    .execute(database.pool())
    .await
    .unwrap();
    assert_eq!(
        store
            .prepare(input(
                &creator,
                &reader,
                "marketplace-payment:order-1:attempt-1",
                b"request-one",
            ))
            .await,
        Err(PersistenceError::CorruptOrMissing)
    );

    database.cleanup().await;
}

#[tokio::test]
async fn non_unique_insert_failure_is_not_an_idempotency_conflict() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let creator = creator();
    let reader = reader();

    sqlx::query(
        "CREATE FUNCTION reject_marketplace_preparation() RETURNS trigger AS $$
         BEGIN
             RAISE EXCEPTION 'forced non-unique insertion failure' USING ERRCODE = '23514';
         END;
         $$ LANGUAGE plpgsql",
    )
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER reject_marketplace_preparation
         BEFORE INSERT ON marketplace_payment_preparations
         FOR EACH ROW EXECUTE FUNCTION reject_marketplace_preparation()",
    )
    .execute(database.pool())
    .await
    .unwrap();

    assert_eq!(
        store
            .prepare(input(
                &creator,
                &reader,
                "marketplace-payment:order-2:attempt-1",
                b"request-two",
            ))
            .await,
        Err(PersistenceError::CorruptOrMissing),
        "a PostgreSQL check/invariant failure must fail closed, not become Conflict/HTTP 409"
    );

    database.cleanup().await;
}

#[tokio::test]
async fn independent_stores_serialize_same_operation_and_binding() {
    let database = TestDatabase::create().await;
    let first_store = store(&database).await;
    let second_store = MarketplacePreparationStore::new(database.pool(), crypto());
    let creator = creator();
    let reader = reader();

    let (first, second) = tokio::join!(
        first_store.prepare(input(
            &creator,
            &reader,
            "shared-operation",
            b"same-binding"
        )),
        second_store.prepare(input(
            &creator,
            &reader,
            "shared-operation",
            b"same-binding"
        )),
    );
    let first = first.unwrap();
    let second = second.unwrap();
    assert_eq!(first.invoice_id(), second.invoice_id());
    assert_ne!(first.replayed(), second.replayed());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM marketplace_payment_preparations")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT next_child_index FROM creators")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        1,
        "concurrent exact retry allocated a duplicate address"
    );

    database.cleanup().await;
}

#[tokio::test]
async fn activation_and_prepare_replay_share_creator_before_preparation_lock_order() {
    let database = TestDatabase::create().await;
    let activation_store = store(&database).await;
    let replay_store = MarketplacePreparationStore::new(database.pool(), crypto());
    let creator = creator();
    let reader = reader();
    let operation_id = "marketplace-payment:activation-replay-lock-order:attempt-1";
    let request_binding = b"activation-replay-lock-order";
    let prepared = activation_store
        .prepare(input(&creator, &reader, operation_id, request_binding))
        .await
        .unwrap();
    let prepared_id = prepared.invoice_id();

    let lock_key = i64::from_be_bytes(uuid::Uuid::new_v4().as_bytes()[..8].try_into().unwrap());
    let mut activation_gate = database.pool().begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(lock_key)
        .execute(&mut *activation_gate)
        .await
        .unwrap();
    sqlx::query(&format!(
        "CREATE FUNCTION hold_marketplace_activation() RETURNS TRIGGER AS $$
         BEGIN
             PERFORM pg_advisory_xact_lock({lock_key});
             RETURN NEW;
         END;
         $$ LANGUAGE plpgsql"
    ))
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER hold_marketplace_activation
         BEFORE UPDATE OF state ON marketplace_payment_preparations
         FOR EACH ROW WHEN (NEW.state = 'active' AND OLD.state = 'prepared')
         EXECUTE FUNCTION hold_marketplace_activation()",
    )
    .execute(database.pool())
    .await
    .unwrap();

    let activate = tokio::spawn({
        let creator = creator.clone();
        async move {
            activation_store
                .activate(MarketplaceActivationInput {
                    creator: &creator,
                    invoice_id: prepared_id,
                    amount: 100,
                    asset: CriterionAsset::Btc,
                    proposal_acceptance_window: std::time::Duration::from_secs(30 * 60),
                })
                .await
        }
    });
    wait_for_lock_waiters(&database, 1).await;

    let replay = tokio::spawn({
        let creator = creator.clone();
        let reader = reader.clone();
        async move {
            replay_store
                .prepare(input(&creator, &reader, operation_id, request_binding))
                .await
        }
    });
    wait_for_lock_waiters(&database, 2).await;
    activation_gate.rollback().await.unwrap();

    let (activated, replayed) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(activate, replay)
    })
    .await
    .expect("activation and exact prepare replay must not deadlock");
    let activated = activated.unwrap().unwrap().unwrap();
    let replayed = replayed.unwrap().unwrap();
    assert!(!activated.replayed());
    assert!(replayed.replayed());
    assert_eq!(activated.invoice_id(), prepared_id);
    assert_eq!(replayed.invoice_id(), prepared_id);

    database.cleanup().await;
}

#[tokio::test]
async fn independent_stores_conflict_on_changed_binding() {
    let database = TestDatabase::create().await;
    let first_store = store(&database).await;
    let second_store = MarketplacePreparationStore::new(database.pool(), crypto());
    let creator = creator();
    let reader = reader();

    let (first, second) = tokio::join!(
        first_store.prepare(input(
            &creator,
            &reader,
            "shared-operation",
            b"first-binding"
        )),
        second_store.prepare(input(
            &creator,
            &reader,
            "shared-operation",
            b"second-binding"
        )),
    );
    assert!(matches!(
        (first, second),
        (Ok(_), Err(PersistenceError::Conflict)) | (Err(PersistenceError::Conflict), Ok(_))
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM marketplace_payment_preparations")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT next_child_index FROM creators")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        1
    );

    database.cleanup().await;
}

#[tokio::test]
async fn same_operation_id_is_independent_across_creators() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let first_creator = creator();
    let second_creator = other_creator();
    create_creator(&database, first_creator.clone(), "first-session", 9).await;
    create_creator(&database, second_creator.clone(), "second-session", 10).await;
    let first_store = MarketplacePreparationStore::new(database.pool(), crypto());
    let second_store = MarketplacePreparationStore::new(database.pool(), crypto());
    let reader = reader();

    let (first, second) = tokio::join!(
        first_store.prepare(input(
            &first_creator,
            &reader,
            "shared-operation",
            b"same-binding"
        )),
        second_store.prepare(input(
            &second_creator,
            &reader,
            "shared-operation",
            b"same-binding"
        )),
    );
    let first = first.unwrap();
    let second = second.unwrap();
    assert_ne!(first.invoice_id(), second.invoice_id());
    assert!(!first.replayed());
    assert!(!second.replayed());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM marketplace_payment_preparations")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        2
    );
    let child_indexes = sqlx::query_scalar::<_, i64>(
        "SELECT next_child_index FROM creators ORDER BY creator_lookup_hash",
    )
    .fetch_all(database.pool())
    .await
    .unwrap();
    assert_eq!(child_indexes, vec![1, 1]);

    database.cleanup().await;
}

#[tokio::test]
async fn activate_starts_db_window_once_and_void_competes_on_the_preparation_row() {
    let database = TestDatabase::create().await;
    let first_store = store(&database).await;
    let second_store = MarketplacePreparationStore::new(database.pool(), crypto());
    let creator = creator();
    let reader = reader();
    let prepared = first_store
        .prepare(input(
            &creator,
            &reader,
            "marketplace-payment:race:attempt-1",
            b"race-request",
        ))
        .await
        .unwrap();
    let prepared_id = prepared.invoice_id();

    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let activate = tokio::spawn({
        let barrier = barrier.clone();
        let store = first_store.clone();
        let creator = creator.clone();
        let invoice_id = prepared_id;
        async move {
            barrier.wait().await;
            store
                .activate(MarketplaceActivationInput {
                    creator: &creator,
                    invoice_id,
                    amount: 100,
                    asset: CriterionAsset::Btc,
                    proposal_acceptance_window: std::time::Duration::from_secs(30 * 60),
                })
                .await
        }
    });
    let void = tokio::spawn({
        let barrier = barrier.clone();
        let store = second_store.clone();
        let creator = creator.clone();
        let invoice_id = prepared_id;
        async move {
            barrier.wait().await;
            store.void(&creator, invoice_id).await
        }
    });
    barrier.wait().await;
    let (activated, voided) = tokio::join!(activate, void);
    let activated = activated.unwrap();
    let voided = voided.unwrap();

    assert!(
        matches!(
            (&activated, &voided),
            (
                Ok(Some(_)),
                Err(MarketplaceLifecyclePersistenceError::InvoiceActive)
            )
        ) || matches!(
            (&activated, &voided),
            (
                Err(MarketplaceLifecyclePersistenceError::LifecycleTerminal),
                Ok(Some(_))
            )
        ),
        "exactly one lifecycle transition must commit: activate={activated:?}, void={voided:?}"
    );
    let state: String =
        sqlx::query_scalar("SELECT state FROM marketplace_payment_preparations WHERE id = $1")
            .bind(prepared_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    let outbox_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM outbox WHERE marketplace_preparation_id = $1")
            .bind(prepared_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(outbox_count, i64::from(state == "active"));
    let settlement_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM marketplace_settlements WHERE preparation_id = $1",
    )
    .bind(prepared_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(settlement_count, i64::from(state == "active"));

    if let Ok(Some(activated)) = activated {
        assert_eq!(
            activated.payment_deadline() - activated.activated_at(),
            time::Duration::days(1)
        );
        assert_eq!(activated.terms().amount(), 100);
        assert!(!activated.replayed());
        let replay = first_store
            .activate(MarketplaceActivationInput {
                creator: &creator,
                invoice_id: prepared_id,
                amount: 100,
                asset: CriterionAsset::Btc,
                proposal_acceptance_window: std::time::Duration::from_secs(30 * 60),
            })
            .await
            .unwrap()
            .unwrap();
        assert!(replay.replayed());
        assert_eq!(replay.activated_at(), activated.activated_at());
        assert_eq!(replay.payment_deadline(), activated.payment_deadline());
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM outbox WHERE marketplace_preparation_id = $1",
            )
            .bind(prepared_id)
            .fetch_one(database.pool())
            .await
            .unwrap(),
            1,
            "activation replay inserted another proposal intent"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM marketplace_settlements WHERE preparation_id = $1",
            )
            .bind(prepared_id)
            .fetch_one(database.pool())
            .await
            .unwrap(),
            1,
            "activation replay inserted another settlement"
        );
        let settlement: (String, i32, bool) = sqlx::query_as(
            "SELECT payment_status, confirmation_count, amount_matched
             FROM marketplace_settlements WHERE preparation_id = $1",
        )
        .bind(prepared_id)
        .fetch_one(database.pool())
        .await
        .unwrap();
        assert_eq!(settlement, ("undetected".into(), 0, false));
        let outbox = OutboxStore::new(database.pool(), crypto());
        let claims = outbox
            .claim(uuid::Uuid::new_v4(), 10, std::time::Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(claims.len(), 1, "active proposal intent must be claimable");
        let intent = outbox.delivery_intent(&claims[0]).unwrap();
        let terms = intent.terms().unwrap();
        assert!(terms.proposal_expires_at.is_some());
        assert_eq!(
            parse_rfc3339(terms.payment_deadline.as_deref().unwrap()),
            activated.payment_deadline()
        );
    } else {
        let replay = second_store
            .void(&creator, prepared_id)
            .await
            .unwrap()
            .unwrap();
        assert!(replay.replayed());
        assert_eq!(replay.invoice_id(), prepared_id);
    }

    database.cleanup().await;
}

#[tokio::test]
async fn settlement_address_collision_is_integrity_failure_and_rolls_back_activation() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let first_creator = creator();
    let second_creator = other_creator();
    create_creator(&database, first_creator.clone(), "first-session", 9).await;
    create_creator(&database, second_creator.clone(), "second-session", 10).await;
    let store = MarketplacePreparationStore::new(database.pool(), crypto());
    let reader = reader();

    let first = store
        .prepare(input(
            &first_creator,
            &reader,
            "first-operation",
            b"first-binding",
        ))
        .await
        .unwrap();
    let second = store
        .prepare(input(
            &second_creator,
            &reader,
            "second-operation",
            b"second-binding",
        ))
        .await
        .unwrap();

    store
        .activate(MarketplaceActivationInput {
            creator: &first_creator,
            invoice_id: first.invoice_id(),
            amount: 100,
            asset: CriterionAsset::Btc,
            proposal_acceptance_window: std::time::Duration::from_secs(30 * 60),
        })
        .await
        .unwrap();
    assert_eq!(
        store
            .activate(MarketplaceActivationInput {
                creator: &second_creator,
                invoice_id: second.invoice_id(),
                amount: 100,
                asset: CriterionAsset::Btc,
                proposal_acceptance_window: std::time::Duration::from_secs(30 * 60),
            })
            .await,
        Err(MarketplaceLifecyclePersistenceError::Persistence(
            PersistenceError::CorruptOrMissing
        ))
    );

    let second_state: (String, Option<OffsetDateTime>, Option<OffsetDateTime>) = sqlx::query_as(
        "SELECT state, activated_at, payment_deadline
             FROM marketplace_payment_preparations WHERE id = $1",
    )
    .bind(second.invoice_id())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(second_state, ("prepared".into(), None, None));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM marketplace_settlements WHERE preparation_id = $1",
        )
        .bind(second.invoice_id())
        .fetch_one(database.pool())
        .await
        .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM outbox WHERE marketplace_preparation_id = $1",
        )
        .bind(second.invoice_id())
        .fetch_one(database.pool())
        .await
        .unwrap(),
        0
    );

    database.cleanup().await;
}

#[tokio::test]
async fn activation_rejects_wrong_total_expiry_and_prepared_resolution_without_publication() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let creator = creator();
    let reader = reader();

    let wrong_total = store
        .prepare(input(
            &creator,
            &reader,
            "marketplace-payment:wrong-total:attempt-1",
            b"wrong-total",
        ))
        .await
        .unwrap();
    assert_eq!(
        store
            .activate(MarketplaceActivationInput {
                creator: &creator,
                invoice_id: wrong_total.invoice_id(),
                amount: 101,
                asset: CriterionAsset::Btc,
                proposal_acceptance_window: std::time::Duration::from_secs(30 * 60),
            })
            .await,
        Err(MarketplaceLifecyclePersistenceError::TotalMismatch)
    );

    let expired = store
        .prepare(input_with_ttl(
            &creator,
            &reader,
            "marketplace-payment:expired:attempt-1",
            b"expired",
            1,
        ))
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    assert_eq!(
        store
            .activate(MarketplaceActivationInput {
                creator: &creator,
                invoice_id: expired.invoice_id(),
                amount: 101,
                asset: CriterionAsset::Btc,
                proposal_acceptance_window: std::time::Duration::from_secs(30 * 60),
            })
            .await,
        Err(MarketplaceLifecyclePersistenceError::PrepareExpired)
    );

    let resolved = store
        .prepare(input(
            &creator,
            &reader,
            "marketplace-payment:resolved:attempt-1",
            b"resolved",
        ))
        .await
        .unwrap();
    store
        .resolve(
            &creator,
            resolved.invoice_id(),
            MarketplaceResolutionOutcome::Abandoned,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .activate(MarketplaceActivationInput {
                creator: &creator,
                invoice_id: resolved.invoice_id(),
                amount: 101,
                asset: CriterionAsset::Btc,
                proposal_acceptance_window: std::time::Duration::from_secs(30 * 60),
            })
            .await,
        Err(MarketplaceLifecyclePersistenceError::LifecycleTerminal)
    );
    assert!(
        store
            .void(&creator, resolved.invoice_id())
            .await
            .unwrap()
            .is_some()
    );

    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM outbox")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM marketplace_settlements")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        0,
        "failed, prepared, and voided activations must not create settlements"
    );
    database.cleanup().await;
}

#[tokio::test]
async fn resolution_annotates_prepared_active_and_voided_without_changing_lifecycle_facts() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let creator = creator();
    let reader = reader();
    let prepared = store
        .prepare(input(
            &creator,
            &reader,
            "marketplace-payment:resolve-prepared:attempt-1",
            b"resolve-prepared",
        ))
        .await
        .unwrap();
    let active = store
        .prepare(input(
            &creator,
            &reader,
            "marketplace-payment:resolve-active:attempt-1",
            b"resolve-active",
        ))
        .await
        .unwrap();
    let activated = store
        .activate(MarketplaceActivationInput {
            creator: &creator,
            invoice_id: active.invoice_id(),
            amount: 100,
            asset: CriterionAsset::Btc,
            proposal_acceptance_window: std::time::Duration::from_secs(30 * 60),
        })
        .await
        .unwrap()
        .unwrap();
    let voided = store
        .prepare(input(
            &creator,
            &reader,
            "marketplace-payment:resolve-voided:attempt-1",
            b"resolve-voided",
        ))
        .await
        .unwrap();
    let void_result = store
        .void(&creator, voided.invoice_id())
        .await
        .unwrap()
        .unwrap();

    for (invoice_id, outcome) in [
        (
            prepared.invoice_id(),
            MarketplaceResolutionOutcome::Abandoned,
        ),
        (
            active.invoice_id(),
            MarketplaceResolutionOutcome::PaidManually,
        ),
        (voided.invoice_id(), MarketplaceResolutionOutcome::Refunded),
    ] {
        let result = store
            .resolve(&creator, invoice_id, outcome)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.invoice_id(), invoice_id);
        assert_eq!(result.outcome(), outcome);
        assert!(!result.replayed());
    }

    let rows: Vec<MarketplaceLifecycleFacts> = sqlx::query_as(
        "SELECT id, state, activated_at, payment_deadline, voided_at
             FROM marketplace_payment_preparations ORDER BY prepared_at",
    )
    .fetch_all(database.pool())
    .await
    .unwrap();
    assert_eq!(
        rows[0],
        (prepared.invoice_id(), "prepared".into(), None, None, None)
    );
    assert_eq!(
        rows[1],
        (
            active.invoice_id(),
            "active".into(),
            Some(activated.activated_at()),
            Some(activated.payment_deadline()),
            None,
        )
    );
    assert_eq!(
        rows[2],
        (
            voided.invoice_id(),
            "voided".into(),
            None,
            None,
            Some(void_result.voided_at()),
        )
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM outbox")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        1,
        "resolution must not add publication or cancellation work"
    );
    database.cleanup().await;
}

#[tokio::test]
async fn resolution_uses_db_clock_and_preserves_creator_ownership_privacy() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let creator = creator();
    let prepared = store
        .prepare(input(
            &creator,
            &reader(),
            "marketplace-payment:resolve-owner:attempt-1",
            b"resolve-owner",
        ))
        .await
        .unwrap();

    assert!(
        store
            .resolve(
                &other_creator(),
                prepared.invoice_id(),
                MarketplaceResolutionOutcome::Refunded,
            )
            .await
            .unwrap()
            .is_none(),
        "creator mismatch must be indistinguishable from an unknown invoice"
    );

    let before: OffsetDateTime = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(database.pool())
        .await
        .unwrap();
    let resolved = store
        .resolve(
            &creator,
            prepared.invoice_id(),
            MarketplaceResolutionOutcome::Refunded,
        )
        .await
        .unwrap()
        .unwrap();
    let after: OffsetDateTime = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(database.pool())
        .await
        .unwrap();
    let stored: OffsetDateTime = sqlx::query_scalar(
        "SELECT resolved_at FROM marketplace_payment_preparations WHERE id = $1",
    )
    .bind(prepared.invoice_id())
    .fetch_one(database.pool())
    .await
    .unwrap();

    assert!(resolved.resolved_at() >= before && resolved.resolved_at() <= after);
    assert_eq!(resolved.resolved_at(), stored);
    let rfc3339 = resolved.resolved_at().format(&Rfc3339).unwrap();
    assert_eq!(
        OffsetDateTime::parse(&rfc3339, &Rfc3339).unwrap(),
        resolved.resolved_at()
    );
    database.cleanup().await;
}

#[tokio::test]
async fn concurrent_same_resolution_replays_one_db_timestamp() {
    let database = TestDatabase::create().await;
    let first_store = store(&database).await;
    let second_store = MarketplacePreparationStore::new(database.pool(), crypto());
    let creator = creator();
    let prepared = first_store
        .prepare(input(
            &creator,
            &reader(),
            "marketplace-payment:resolve-replay:attempt-1",
            b"resolve-replay",
        ))
        .await
        .unwrap();
    let prepared_id = prepared.invoice_id();
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let first = tokio::spawn({
        let barrier = barrier.clone();
        let creator = creator.clone();
        async move {
            barrier.wait().await;
            first_store
                .resolve(
                    &creator,
                    prepared_id,
                    MarketplaceResolutionOutcome::PaidManually,
                )
                .await
        }
    });
    let second = tokio::spawn({
        let barrier = barrier.clone();
        let creator = creator.clone();
        async move {
            barrier.wait().await;
            second_store
                .resolve(
                    &creator,
                    prepared_id,
                    MarketplaceResolutionOutcome::PaidManually,
                )
                .await
        }
    });
    barrier.wait().await;
    let first = first.await.unwrap().unwrap().unwrap();
    let second = second.await.unwrap().unwrap().unwrap();

    assert_ne!(first.replayed(), second.replayed());
    assert_eq!(first.resolved_at(), second.resolved_at());
    assert_eq!(first.outcome(), MarketplaceResolutionOutcome::PaidManually);
    assert_eq!(second.outcome(), MarketplaceResolutionOutcome::PaidManually);
    database.cleanup().await;
}

#[tokio::test]
async fn concurrent_different_resolutions_commit_one_immutable_outcome() {
    let database = TestDatabase::create().await;
    let first_store = store(&database).await;
    let second_store = MarketplacePreparationStore::new(database.pool(), crypto());
    let creator = creator();
    let prepared = first_store
        .prepare(input(
            &creator,
            &reader(),
            "marketplace-payment:resolve-conflict:attempt-1",
            b"resolve-conflict",
        ))
        .await
        .unwrap();
    let prepared_id = prepared.invoice_id();
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let first = tokio::spawn({
        let barrier = barrier.clone();
        let creator = creator.clone();
        async move {
            barrier.wait().await;
            first_store
                .resolve(
                    &creator,
                    prepared_id,
                    MarketplaceResolutionOutcome::Refunded,
                )
                .await
        }
    });
    let second = tokio::spawn({
        let barrier = barrier.clone();
        let creator = creator.clone();
        async move {
            barrier.wait().await;
            second_store
                .resolve(
                    &creator,
                    prepared_id,
                    MarketplaceResolutionOutcome::Abandoned,
                )
                .await
        }
    });
    barrier.wait().await;
    let (first, second) = (first.await.unwrap(), second.await.unwrap());
    assert!(
        matches!(
            (&first, &second),
            (
                Ok(Some(_)),
                Err(MarketplaceLifecyclePersistenceError::ResolutionConflict)
            )
        ) || matches!(
            (&first, &second),
            (
                Err(MarketplaceLifecyclePersistenceError::ResolutionConflict),
                Ok(Some(_))
            )
        ),
        "exactly one outcome must commit: first={first:?}, second={second:?}"
    );
    let stored: String = sqlx::query_scalar(
        "SELECT business_outcome FROM marketplace_payment_preparations WHERE id = $1",
    )
    .bind(prepared_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert!(matches!(stored.as_str(), "refunded" | "abandoned"));
    let rewrite = sqlx::query(
        "UPDATE marketplace_payment_preparations
         SET business_outcome = 'paid_manually', resolved_at = clock_timestamp()
         WHERE id = $1",
    )
    .bind(prepared_id)
    .execute(database.pool())
    .await
    .unwrap_err();
    assert_eq!(
        rewrite.as_database_error().unwrap().code().as_deref(),
        Some("23514")
    );
    database.cleanup().await;
}

#[tokio::test]
async fn prepared_resolution_and_activation_serialize_without_unresolved_publication() {
    let database = TestDatabase::create().await;
    let activation_store = store(&database).await;
    let resolution_store = MarketplacePreparationStore::new(database.pool(), crypto());
    let creator = creator();
    let prepared = activation_store
        .prepare(input(
            &creator,
            &reader(),
            "marketplace-payment:resolve-activate:attempt-1",
            b"resolve-activate",
        ))
        .await
        .unwrap();
    let prepared_id = prepared.invoice_id();
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let activate = tokio::spawn({
        let barrier = barrier.clone();
        let creator = creator.clone();
        async move {
            barrier.wait().await;
            activation_store
                .activate(MarketplaceActivationInput {
                    creator: &creator,
                    invoice_id: prepared_id,
                    amount: 100,
                    asset: CriterionAsset::Btc,
                    proposal_acceptance_window: std::time::Duration::from_secs(30 * 60),
                })
                .await
        }
    });
    let resolve = tokio::spawn({
        let barrier = barrier.clone();
        let creator = creator.clone();
        async move {
            barrier.wait().await;
            resolution_store
                .resolve(
                    &creator,
                    prepared_id,
                    MarketplaceResolutionOutcome::Abandoned,
                )
                .await
        }
    });
    barrier.wait().await;
    let activated = activate.await.unwrap();
    let resolved = resolve.await.unwrap().unwrap().unwrap();
    assert!(!resolved.replayed());
    let state: String =
        sqlx::query_scalar("SELECT state FROM marketplace_payment_preparations WHERE id = $1")
            .bind(prepared_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    let outbox_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM outbox WHERE marketplace_preparation_id = $1")
            .bind(prepared_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    match activated {
        Ok(Some(_)) => {
            assert_eq!(state, "active");
            assert_eq!(outbox_count, 1);
        }
        Err(MarketplaceLifecyclePersistenceError::LifecycleTerminal) => {
            assert_eq!(state, "prepared");
            assert_eq!(outbox_count, 0);
        }
        other => panic!("unexpected activation result: {other:?}"),
    }
    database.cleanup().await;
}

#[tokio::test]
async fn sub_microsecond_deadline_is_stored_as_postgresql_keeps_it() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let creator = creator();
    let reader = reader();
    let deadline = (OffsetDateTime::now_utc() + time::Duration::minutes(15))
        .replace_nanosecond(123_456_789)
        .unwrap();
    let mut prepared_input = input(&creator, &reader, "nanos", b"nanos");
    prepared_input.prepare_deadline = Some(deadline);
    let prepared = store.prepare(prepared_input).await.unwrap();
    assert_eq!(
        prepared.prepare_expires_at(),
        deadline.replace_nanosecond(123_456_000).unwrap()
    );
    let stored: OffsetDateTime = sqlx::query_scalar(
        "SELECT prepare_expires_at FROM marketplace_payment_preparations WHERE id = $1",
    )
    .bind(prepared.invoice_id())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(stored, prepared.prepare_expires_at());
    store
        .activate(MarketplaceActivationInput {
            creator: &creator,
            invoice_id: prepared.invoice_id(),
            amount: 100,
            asset: CriterionAsset::Btc,
            proposal_acceptance_window: std::time::Duration::from_secs(30 * 60),
        })
        .await
        .unwrap()
        .unwrap();
    database.cleanup().await;
}

#[tokio::test]
async fn shortest_payment_window_still_has_a_usable_proposal_interval() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let creator = creator();
    let reader = reader();
    let prepared = store
        .prepare(input_with_ttl_and_window(
            &creator,
            &reader,
            "marketplace-payment:short-window:attempt-1",
            b"short-window",
            60,
            1,
        ))
        .await
        .unwrap();

    let activated = store
        .activate(MarketplaceActivationInput {
            creator: &creator,
            invoice_id: prepared.invoice_id(),
            amount: 100,
            asset: CriterionAsset::Btc,
            proposal_acceptance_window: std::time::Duration::from_secs(30 * 60),
        })
        .await
        .unwrap()
        .unwrap();
    let outbox = OutboxStore::new(database.pool(), crypto());
    let claims = outbox
        .claim(uuid::Uuid::new_v4(), 1, std::time::Duration::from_secs(30))
        .await
        .unwrap();
    let intent = outbox.delivery_intent(&claims[0]).unwrap();
    let proposal_expires_at = OffsetDateTime::parse(
        intent
            .terms()
            .unwrap()
            .proposal_expires_at
            .as_deref()
            .unwrap(),
        &Rfc3339,
    )
    .unwrap();

    assert!(activated.activated_at() < proposal_expires_at);
    assert!(proposal_expires_at < activated.payment_deadline());
    assert_eq!(
        proposal_expires_at - activated.activated_at(),
        time::Duration::milliseconds(500),
        "one-second payment window must retain exact half-window precision"
    );
    assert_eq!(
        activated.payment_deadline() - activated.activated_at(),
        time::Duration::seconds(1)
    );
    database.cleanup().await;
}

#[tokio::test]
async fn configured_subsecond_policy_wins_below_half_payment_window() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let creator = creator();
    let reader = reader();
    let prepared = store
        .prepare(input_with_ttl_and_window(
            &creator,
            &reader,
            "marketplace-payment:subsecond-policy:attempt-1",
            b"subsecond-policy",
            60,
            5,
        ))
        .await
        .unwrap();

    let activated = store
        .activate(MarketplaceActivationInput {
            creator: &creator,
            invoice_id: prepared.invoice_id(),
            amount: 100,
            asset: CriterionAsset::Btc,
            proposal_acceptance_window: std::time::Duration::from_millis(750),
        })
        .await
        .unwrap()
        .unwrap();
    let outbox = OutboxStore::new(database.pool(), crypto());
    let claims = outbox
        .claim(uuid::Uuid::new_v4(), 1, std::time::Duration::from_secs(30))
        .await
        .unwrap();
    let intent = outbox.delivery_intent(&claims[0]).unwrap();
    let proposal_expires_at = OffsetDateTime::parse(
        intent
            .terms()
            .unwrap()
            .proposal_expires_at
            .as_deref()
            .unwrap(),
        &Rfc3339,
    )
    .unwrap();

    assert_eq!(
        proposal_expires_at - activated.activated_at(),
        time::Duration::milliseconds(750)
    );
    assert_eq!(
        activated.payment_deadline() - activated.activated_at(),
        time::Duration::seconds(5)
    );
    database.cleanup().await;
}

#[tokio::test]
async fn authenticated_invalid_stored_intent_is_corrupt_not_caller_input() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let creator = creator();
    let reader = reader();
    let prepared = store
        .prepare(input(
            &creator,
            &reader,
            "marketplace-payment:invalid-stored-intent:attempt-1",
            b"invalid-stored-intent",
        ))
        .await
        .unwrap();
    let encrypted: Vec<u8> = sqlx::query_scalar(
        "SELECT preparation_envelope FROM marketplace_payment_preparations WHERE id = $1",
    )
    .bind(prepared.invoice_id())
    .fetch_one(database.pool())
    .await
    .unwrap();
    let crypto = crypto();
    let context = EnvelopeContext::marketplace_preparation(
        crypto.lookup_hash(creator.to_string().as_bytes()),
        prepared.invoice_id(),
    );
    let plaintext = crypto
        .decrypt(&context, &EncryptedEnvelope::from_bytes(encrypted))
        .unwrap();
    let mut envelope: StoredPreparationEnvelope = postcard::from_bytes(&plaintext).unwrap();
    envelope.reference = "53efc9fd-72b2-47b7-94c4-1d66dcad0018".into();
    let tampered = crypto
        .encrypt(&context, &postcard::to_allocvec(&envelope).unwrap())
        .unwrap();
    sqlx::query(
        "UPDATE marketplace_payment_preparations SET preparation_envelope = $2 WHERE id = $1",
    )
    .bind(prepared.invoice_id())
    .bind(tampered.as_bytes())
    .execute(database.pool())
    .await
    .unwrap();

    assert_eq!(
        store
            .activate(MarketplaceActivationInput {
                creator: &creator,
                invoice_id: prepared.invoice_id(),
                amount: 100,
                asset: CriterionAsset::Btc,
                proposal_acceptance_window: std::time::Duration::from_secs(30 * 60),
            })
            .await,
        Err(MarketplaceLifecyclePersistenceError::Persistence(
            PersistenceError::CorruptOrMissing
        ))
    );
    database.cleanup().await;
}
