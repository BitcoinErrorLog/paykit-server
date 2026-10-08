use std::sync::Arc;

use paykit_sdk::PaykitIdentitySecretKey;
use paykit_server::{
    application::semantic_intent::DeliveryIntentV1,
    crypto::{Crypto, EncryptedEnvelope, EnvelopeContext},
    domain::locks::{CreatorPubky, ReaderPubky, parse_bundle_id, parse_creator, parse_reader},
    persistence::{
        AtomicInvoiceInput, CreatorCredentials, CreatorStore, InvoicePayloadFactory,
        InvoicePayloads, InvoiceStore, PersistenceError, run_migrations,
    },
};
use paykit_server_e2e::postgres::TestDatabase;
use sqlx::Row;

const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";
mod common;

struct TestPayloads;
impl InvoicePayloadFactory for TestPayloads {
    fn for_child_index(&self, child_index: i64) -> Result<InvoicePayloads, PersistenceError> {
        Ok(InvoicePayloads {
            payment_request_intent: payment_intent(format!("test-address-{child_index}")),
        })
    }
}

struct EmptyAddressPayloads;
impl InvoicePayloadFactory for EmptyAddressPayloads {
    fn for_child_index(&self, _child_index: i64) -> Result<InvoicePayloads, PersistenceError> {
        Ok(InvoicePayloads {
            payment_request_intent: payment_intent(String::new()),
        })
    }
}

struct CreatorPayloads {
    address_prefix: &'static str,
}

impl InvoicePayloadFactory for CreatorPayloads {
    fn for_child_index(&self, child_index: i64) -> Result<InvoicePayloads, PersistenceError> {
        let address = format!("{}-{child_index}", self.address_prefix);
        Ok(InvoicePayloads {
            payment_request_intent: payment_intent(address.clone()),
        })
    }
}

fn payment_intent(address: String) -> DeliveryIntentV1 {
    common::payment_intent(&reader(), address)
}

static TEST_PAYLOADS: TestPayloads = TestPayloads;

fn crypto() -> Arc<Crypto> {
    Arc::new(Crypto::from_master_key(&[7; 32]).unwrap())
}

fn creator() -> CreatorPubky {
    parse_creator(CREATOR).unwrap()
}

fn second_creator() -> CreatorPubky {
    for replacement in "ybndrfg8ejkmcpqxot1uwisza345h769".chars() {
        let mut candidate = CREATOR.to_owned();
        candidate.replace_range(6..7, &replacement.to_string());
        if let Ok(candidate) = parse_creator(&candidate)
            && candidate != creator()
        {
            return candidate;
        }
    }
    panic!("second valid creator fixture")
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

fn second_reader() -> ReaderPubky {
    parse_reader(&second_creator().to_string()).unwrap()
}

async fn invoice_store(database: &TestDatabase) -> InvoiceStore {
    run_migrations(database.pool()).await.unwrap();
    let crypto = crypto();
    CreatorStore::new(database.pool(), crypto.clone())
        .create(&CreatorCredentials::new(
            creator(),
            "session-secret".into(),
            PaykitIdentitySecretKey::new([9; 32], 1).unwrap(),
            Some(paykit_server::domain::receiving::BitcoinAccount {
                xpub: "xpub-secret".to_owned().into(),
                account_index: 0,
            }),
            None,
        ))
        .await
        .unwrap();
    InvoiceStore::new(database.pool(), crypto)
}

fn input<'a>(
    creator: &'a CreatorPubky,
    reader: &'a ReaderPubky,
    bundle: &'a [u8],
    request: &'a [u8],
) -> AtomicInvoiceInput<'a> {
    AtomicInvoiceInput {
        creator,
        reader,
        bundle_binding: bundle,
        lock_resource_binding: request,
        payment_request_binding: request,
        invoice_payloads: &TEST_PAYLOADS,

        proposal_acceptance_seconds: 60 * 60,
        payment_window_seconds: 24 * 60 * 60,
    }
}

#[tokio::test]
async fn committed_admissions_coalesce_and_failed_commits_do_not_wake() {
    let database = TestDatabase::create().await;
    let store = invoice_store(&database).await;
    let clone = store.clone();
    let creator = creator();
    let reader = reader();
    for bundle in [b"wake-one".as_slice(), b"wake-two"] {
        store
            .create_atomic(input(&creator, &reader, bundle, bundle))
            .await
            .unwrap();
    }
    tokio::time::timeout(std::time::Duration::ZERO, clone.wait_for_admission())
        .await
        .expect("committed work retains a wakeup before the worker waits");
    assert!(
        tokio::time::timeout(std::time::Duration::ZERO, store.wait_for_admission())
            .await
            .is_err()
    );
    let restarted = InvoiceStore::new(database.pool(), crypto());
    assert!(
        tokio::time::timeout(std::time::Duration::ZERO, restarted.wait_for_admission())
            .await
            .is_err()
    );
    assert_eq!(
        paykit_server::persistence::OutboxStore::new(database.pool(), crypto())
            .claim(uuid::Uuid::new_v4(), 16, std::time::Duration::from_secs(30))
            .await
            .unwrap()
            .len(),
        2,
        "periodic claims recover durable work without a process-local hint"
    );

    // A deferred trigger fails COMMIT after the outbox INSERT succeeded.
    sqlx::raw_sql(
        "CREATE FUNCTION reject_admission() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN RAISE EXCEPTION 'admission rejected'; END $$;
         CREATE CONSTRAINT TRIGGER reject_admission AFTER INSERT ON outbox
         DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_admission();",
    )
    .execute(database.pool())
    .await
    .unwrap();
    assert!(
        store
            .create_atomic(input(&creator, &reader, b"wake-failed", b"wake-failed"))
            .await
            .is_err()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM outbox")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        2
    );
    assert!(
        tokio::time::timeout(std::time::Duration::ZERO, store.wait_for_admission())
            .await
            .is_err()
    );
    database.cleanup().await;
}

#[tokio::test]
async fn connection_binding_uses_persisted_reader_identity_without_mutating_business_rows() {
    let database = TestDatabase::create().await;
    let invoices = invoice_store(&database).await;
    let creator = creator();
    let reader = reader();
    let bundle = "000G40R40M30E209185GR38E1W";
    invoices
        .create_atomic(input(
            &creator,
            &reader,
            bundle.as_bytes(),
            b"connection-request",
        ))
        .await
        .unwrap();
    let before: Vec<String> =
        sqlx::query_scalar("SELECT row_to_json(o)::text FROM outbox o ORDER BY id")
            .fetch_all(database.pool())
            .await
            .unwrap();
    let binding = invoices
        .connection_binding(&creator, &parse_bundle_id(bundle).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(binding.reader(), &reader);
    assert!(
        invoices
            .connection_binding(&second_creator(), &parse_bundle_id(bundle).unwrap())
            .await
            .unwrap()
            .is_none()
    );
    let after: Vec<String> =
        sqlx::query_scalar("SELECT row_to_json(o)::text FROM outbox o ORDER BY id")
            .fetch_all(database.pool())
            .await
            .unwrap();
    assert_eq!(before, after);
    database.cleanup().await;
}

#[tokio::test]
async fn invoice_allocation_encrypts_bound_terms_and_replays() {
    let database = TestDatabase::create().await;
    let store = invoice_store(&database).await;
    let creator = creator();
    let reader = reader();

    let first = store
        .create_atomic(input(&creator, &reader, b"bundle-one", b"request-one"))
        .await
        .unwrap();
    assert!(!first.replayed());
    assert_eq!(first.reader_child_index(), 0);

    let protected_payment_row = sqlx::query(
        "SELECT payment_record_envelope, bitcoin_address_lookup_hash FROM invoices WHERE id = $1",
    )
    .bind(first.invoice_id())
    .fetch_one(database.pool())
    .await
    .unwrap();
    let payment_record_envelope =
        protected_payment_row.get::<Vec<u8>, _>("payment_record_envelope");
    let address_lookup_hash =
        protected_payment_row.get::<Vec<u8>, _>("bitcoin_address_lookup_hash");
    assert_eq!(
        address_lookup_hash,
        crypto()
            .bitcoin_address_lookup_hash(b"test-address-0")
            .as_bytes()
            .as_slice()
    );
    assert!(
        !payment_record_envelope
            .windows(b"test-address-0".len())
            .any(|window| window == b"test-address-0")
    );

    let payment_row = sqlx::query("SELECT invoice_id, intent_envelope FROM outbox WHERE id = $1")
        .bind(first.payment_request_outbox_id())
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(
        payment_row.get::<Option<_>, _>("invoice_id"),
        Some(first.invoice_id())
    );
    for raw in [
        payment_row.get::<Vec<u8>, _>("intent_envelope"),
        sqlx::query_scalar::<_, Vec<u8>>("SELECT invoice_envelope FROM invoices WHERE id = $1")
            .bind(first.invoice_id())
            .fetch_one(database.pool())
            .await
            .unwrap(),
        sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT assignment_envelope FROM reader_assignments WHERE id = $1",
        )
        .bind(first.reader_assignment_id())
        .fetch_one(database.pool())
        .await
        .unwrap(),
    ] {
        for plaintext in [b"test-address-0".as_slice(), reader.to_string().as_bytes()] {
            assert!(
                !raw.windows(plaintext.len())
                    .any(|window| window == plaintext)
            );
        }
    }

    let original_payment_envelope: Vec<u8> =
        sqlx::query_scalar("SELECT intent_envelope FROM outbox WHERE id = $1")
            .bind(first.payment_request_outbox_id())
            .fetch_one(database.pool())
            .await
            .unwrap();
    let creator_hash = crypto().lookup_hash(creator.to_string().as_bytes());
    let original_plaintext = crypto()
        .decrypt(
            &EnvelopeContext::outbox_semantic_intent(
                creator_hash,
                first.payment_request_outbox_id(),
            ),
            &EncryptedEnvelope::from_bytes(original_payment_envelope.clone()),
        )
        .unwrap();
    let original_intent = DeliveryIntentV1::decode(&original_plaintext).unwrap();
    let original_reference = original_intent.terms().unwrap().payment_reference.clone();
    let original_app_id = original_intent.app_id();

    let replay = store
        .create_atomic(input(&creator, &reader, b"bundle-one", b"request-one"))
        .await
        .unwrap();
    assert!(replay.replayed());
    assert_eq!(replay.invoice_id(), first.invoice_id());
    assert_eq!(
        replay.payment_request_outbox_id(),
        first.payment_request_outbox_id()
    );
    assert_eq!(replay.reader_assignment_id(), first.reader_assignment_id());
    assert_eq!(replay.reader_child_index(), 0);
    let replayed_payment_envelope: Vec<u8> =
        sqlx::query_scalar("SELECT intent_envelope FROM outbox WHERE id = $1")
            .bind(replay.payment_request_outbox_id())
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(replayed_payment_envelope, original_payment_envelope);
    let replayed_plaintext = crypto()
        .decrypt(
            &EnvelopeContext::outbox_semantic_intent(
                creator_hash,
                replay.payment_request_outbox_id(),
            ),
            &EncryptedEnvelope::from_bytes(replayed_payment_envelope),
        )
        .unwrap();
    let replayed_intent = DeliveryIntentV1::decode(&replayed_plaintext).unwrap();
    assert_eq!(replayed_intent.app_id(), original_app_id);
    assert_eq!(
        replayed_intent.terms().unwrap().payment_reference,
        original_reference
    );
    assert_eq!(replayed_intent, original_intent);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM reader_assignments")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM invoices")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM outbox")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .create_atomic(input(&creator, &reader, b"bundle-one", b"changed-request"))
            .await,
        Err(PersistenceError::Conflict)
    );
    assert_eq!(
        store
            .create_atomic(input(
                &creator,
                &second_reader(),
                b"bundle-one",
                b"changed-reader-request",
            ))
            .await,
        Err(PersistenceError::Conflict)
    );

    let second = store
        .create_atomic(input(&creator, &reader, b"bundle-two", b"request-two"))
        .await
        .unwrap();
    assert!(!second.replayed());
    assert_ne!(second.reader_assignment_id(), first.reader_assignment_id());
    assert_eq!(second.reader_child_index(), 1);
    assert_ne!(
        sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT bitcoin_address_lookup_hash FROM invoices WHERE id = $1",
        )
        .bind(first.invoice_id())
        .fetch_one(database.pool())
        .await
        .unwrap(),
        sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT bitcoin_address_lookup_hash FROM invoices WHERE id = $1",
        )
        .bind(second.invoice_id())
        .fetch_one(database.pool())
        .await
        .unwrap(),
    );
    let envelope: Vec<u8> = sqlx::query_scalar("SELECT intent_envelope FROM outbox WHERE id = $1")
        .bind(second.payment_request_outbox_id())
        .fetch_one(database.pool())
        .await
        .unwrap();
    let plaintext = crypto()
        .decrypt(
            &EnvelopeContext::outbox_semantic_intent(
                creator_hash,
                second.payment_request_outbox_id(),
            ),
            &EncryptedEnvelope::from_bytes(envelope),
        )
        .unwrap();
    let second_intent = DeliveryIntentV1::decode(&plaintext).unwrap();
    let first_terms = original_intent.terms().unwrap();
    let second_terms = second_intent.terms().unwrap();
    assert_eq!(
        first_terms.payment_endpoints["btc-bitcoin-p2wpkh"],
        serde_json::json!({"value":"test-address-0"}).to_string()
    );
    assert_eq!(
        second_terms.payment_endpoints["btc-bitcoin-p2wpkh"],
        serde_json::json!({"value":"test-address-1"}).to_string()
    );

    database.cleanup().await;
}

#[tokio::test]
async fn concurrent_exact_invoice_allocation_serializes_to_one_durable_result() {
    let database = TestDatabase::create().await;
    let store = invoice_store(&database).await;
    let other_store = store.clone();
    let creator = creator();
    let reader = reader();

    let (first, second) = tokio::join!(
        store.create_atomic(input(
            &creator,
            &reader,
            b"concurrent-bundle",
            b"concurrent-request"
        )),
        other_store.create_atomic(input(
            &creator,
            &reader,
            b"concurrent-bundle",
            b"concurrent-request"
        ))
    );
    let first = first.unwrap();
    let second = second.unwrap();

    assert_ne!(first.replayed(), second.replayed());
    assert_eq!(first.invoice_id(), second.invoice_id());
    assert_eq!(first.reader_assignment_id(), second.reader_assignment_id());
    assert_eq!(
        first.payment_request_outbox_id(),
        second.payment_request_outbox_id()
    );
    for (table, expected) in [
        ("reader_assignments", 1_i64),
        ("invoices", 1_i64),
        ("outbox", 1_i64),
    ] {
        let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(database.pool())
            .await
            .unwrap();
        assert_eq!(count, expected, "unexpected {table} cardinality");
    }
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
async fn concurrent_invoices_for_same_reader_bind_distinct_addresses() {
    let database = TestDatabase::create().await;
    let store = invoice_store(&database).await;
    let creator = creator();
    let reader = reader();
    let (first, second) = tokio::join!(
        store.create_atomic(input(&creator, &reader, b"bundle-a", b"request-a")),
        store.create_atomic(input(&creator, &reader, b"bundle-b", b"request-b")),
    );
    let first = first.unwrap();
    let second = second.unwrap();
    assert_ne!(first.invoice_id(), second.invoice_id());
    assert_ne!(first.reader_child_index(), second.reader_child_index());
    let outbox = paykit_server::persistence::OutboxStore::new(database.pool(), crypto());
    let claims = outbox
        .claim(uuid::Uuid::new_v4(), 10, std::time::Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(claims.len(), 2, "each invoice is immediately claimable");
    let mut destinations = claims
        .iter()
        .map(|claim| {
            outbox
                .delivery_intent(claim)
                .unwrap()
                .terms()
                .unwrap()
                .payment_endpoints["btc-bitcoin-p2wpkh"]
                .clone()
        })
        .collect::<Vec<_>>();
    destinations.sort();
    assert_eq!(
        destinations,
        [
            serde_json::json!({"value": "test-address-0"}).to_string(),
            serde_json::json!({"value": "test-address-1"}).to_string(),
        ]
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT next_child_index FROM creators")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        2
    );
    database.cleanup().await;
}

#[tokio::test]
async fn atomic_store_rejects_empty_address_and_wrong_reader_before_any_insert() {
    static BAD_PAYLOADS: EmptyAddressPayloads = EmptyAddressPayloads;
    let database = TestDatabase::create().await;
    let store = invoice_store(&database).await;
    let creator = creator();
    let reader = reader();

    let mut mismatched_address = input(&creator, &reader, b"bad-address", b"bad-address-request");
    mismatched_address.invoice_payloads = &BAD_PAYLOADS;
    assert_eq!(
        store.create_atomic(mismatched_address).await,
        Err(PersistenceError::InvalidInput)
    );

    let other_reader = second_reader();
    assert_eq!(
        store
            .create_atomic(input(
                &creator,
                &other_reader,
                b"bad-reader",
                b"bad-reader-request",
            ))
            .await,
        Err(PersistenceError::CorruptOrMissing)
    );
    let counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT
            (SELECT COUNT(*) FROM invoices),
            (SELECT COUNT(*) FROM reader_assignments),
            (SELECT COUNT(*) FROM outbox)",
    )
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(counts, (0, 0, 0));

    database.cleanup().await;
}

#[tokio::test]
async fn allocation_and_invoice_rollback_on_request_outbox_failure() {
    let database = TestDatabase::create().await;
    let store = invoice_store(&database).await;
    let creator = creator();
    let reader = reader();
    sqlx::query(
        "CREATE FUNCTION fail_payment_request_outbox_insert() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN IF NEW.invoice_id IS NOT NULL THEN RAISE EXCEPTION 'forced payment request outbox failure'; END IF; RETURN NEW; END; $$",
    )
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER fail_payment_request_outbox_insert BEFORE INSERT ON outbox \
         FOR EACH ROW EXECUTE FUNCTION fail_payment_request_outbox_insert()",
    )
    .execute(database.pool())
    .await
    .unwrap();

    assert!(
        store
            .create_atomic(input(
                &creator,
                &reader,
                b"rollback-bundle",
                b"rollback-request",
            ))
            .await
            .is_err()
    );
    for table in ["reader_assignments", "invoices", "outbox"] {
        let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(database.pool())
            .await
            .unwrap();
        assert_eq!(count, 0, "{table} escaped the failed transaction");
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT next_child_index FROM creators")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        0,
        "allocator increment escaped the failed transaction"
    );

    database.cleanup().await;
}

#[tokio::test]
async fn concurrent_creators_own_distinct_intents_at_the_same_child_index() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = crypto();
    let creators = CreatorStore::new(database.pool(), crypto.clone());
    let first_creator = creator();
    let second_creator = second_creator();
    creators
        .create(&CreatorCredentials::new(
            first_creator.clone(),
            "session-one".into(),
            PaykitIdentitySecretKey::new([9; 32], 1).unwrap(),
            Some(paykit_server::domain::receiving::BitcoinAccount {
                xpub: "xpub-one".to_owned().into(),
                account_index: 0,
            }),
            None,
        ))
        .await
        .unwrap();
    creators
        .create(&CreatorCredentials::new(
            second_creator.clone(),
            "session-two".into(),
            PaykitIdentitySecretKey::new([8; 32], 1).unwrap(),
            Some(paykit_server::domain::receiving::BitcoinAccount {
                xpub: "xpub-two".to_owned().into(),
                account_index: 0,
            }),
            None,
        ))
        .await
        .unwrap();

    let first_store = InvoiceStore::new(database.pool(), crypto.clone());
    let second_store = first_store.clone();
    let reader = reader();
    let first_payloads = CreatorPayloads {
        address_prefix: "creator-one-address",
    };
    let second_payloads = CreatorPayloads {
        address_prefix: "creator-two-address",
    };
    let (first, second) = tokio::join!(
        first_store.create_atomic(AtomicInvoiceInput {
            creator: &first_creator,
            reader: &reader,
            bundle_binding: b"creator-one-bundle",
            lock_resource_binding: b"creator-one-lock",
            payment_request_binding: b"creator-one-request",
            invoice_payloads: &first_payloads,

            proposal_acceptance_seconds: 60 * 60,
            payment_window_seconds: 24 * 60 * 60,
        }),
        second_store.create_atomic(AtomicInvoiceInput {
            creator: &second_creator,
            reader: &reader,
            bundle_binding: b"creator-two-bundle",
            lock_resource_binding: b"creator-two-lock",
            payment_request_binding: b"creator-two-request",
            invoice_payloads: &second_payloads,

            proposal_acceptance_seconds: 60 * 60,
            payment_window_seconds: 24 * 60 * 60,
        })
    );
    let first = first.unwrap();
    let second = second.unwrap();
    assert_eq!(first.reader_child_index(), 0);
    assert_eq!(second.reader_child_index(), 0);

    let first_hashes: (Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT bitcoin_address_lookup_hash, derivation_index_lookup_hash
         FROM invoices WHERE id = $1",
    )
    .bind(first.invoice_id())
    .fetch_one(database.pool())
    .await
    .unwrap();
    let second_hashes: (Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT bitcoin_address_lookup_hash, derivation_index_lookup_hash
         FROM invoices WHERE id = $1",
    )
    .bind(second.invoice_id())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_ne!(first_hashes.0, second_hashes.0);
    assert_ne!(first_hashes.1, second_hashes.1);

    let first_request = first.payment_request_outbox_id();
    let first_envelope: Vec<u8> =
        sqlx::query_scalar("SELECT intent_envelope FROM outbox WHERE id = $1")
            .bind(first_request)
            .fetch_one(database.pool())
            .await
            .unwrap();
    let first_hash = crypto.lookup_hash(first_creator.to_string().as_bytes());
    let second_hash = crypto.lookup_hash(second_creator.to_string().as_bytes());
    let first_payment_envelope: Vec<u8> =
        sqlx::query_scalar("SELECT payment_record_envelope FROM invoices WHERE id = $1")
            .bind(first.invoice_id())
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert!(
        crypto
            .decrypt(
                &EnvelopeContext::invoice_payment_record(second_hash, first.invoice_id()),
                &EncryptedEnvelope::from_bytes(first_payment_envelope.clone()),
            )
            .is_err(),
        "another Creator context decrypted the first Creator payment record"
    );
    assert!(
        crypto
            .decrypt(
                &EnvelopeContext::invoice_payment_record(first_hash, first.invoice_id()),
                &EncryptedEnvelope::from_bytes(first_payment_envelope),
            )
            .is_ok()
    );
    assert!(
        crypto
            .decrypt(
                &EnvelopeContext::outbox_semantic_intent(second_hash, first_request),
                &EncryptedEnvelope::from_bytes(first_envelope.clone()),
            )
            .is_err(),
        "another Creator context decrypted the first Creator intent"
    );
    let plaintext = crypto
        .decrypt(
            &EnvelopeContext::outbox_semantic_intent(first_hash, first_request),
            &EncryptedEnvelope::from_bytes(first_envelope),
        )
        .unwrap();
    let intent: DeliveryIntentV1 = postcard::from_bytes(&plaintext).unwrap();
    assert_eq!(
        intent.terms().unwrap().payment_endpoints["btc-bitcoin-p2wpkh"],
        serde_json::json!({"value": "creator-one-address-0"}).to_string()
    );

    database.cleanup().await;
}
