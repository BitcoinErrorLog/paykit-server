use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use paykit_lib::PaykitAppRegistry;
use paykit_sdk::{
    LinkedPeerState, OutboundPrivateMessageStatus, PaykitIdentitySecretKey, PubkyLocalSecretKey,
    PubkyPublicKey, PubkySessionBootstrap, StorageAdapter,
};
use paykit_server::{
    config::{PaykitConfig, PaykitNetwork},
    crypto::Crypto,
    domain::locks::{CreatorPubky, ReaderPubky, parse_creator, parse_reader},
    paykit::{CreatorSessions, PaykitAdapter},
    persistence::{
        AtomicInvoiceInput, CreatorCredentials, CreatorStore, InvoicePayloadFactory,
        InvoicePayloads, InvoiceStore, OutboxRetryClass, OutboxStore, PersistenceError,
        run_migrations,
    },
    workers::outbox::{
        Adapter, HandoffError, HandoffResult, process_claim, process_reconciliation,
        with_claim_renewal,
    },
};
use paykit_server_e2e::postgres::TestDatabase;
use pubky_testnet::{EphemeralTestnet, pubky::Keypair};
use uuid::Uuid;

mod common;
#[path = "fixtures/sdk.rs"]
mod sdk_fixtures;

const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";

async fn queued_invoice(database: &TestDatabase) -> OutboxStore {
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[7; 32]).unwrap());
    let creator = creator();
    let reader = reader();
    CreatorStore::new(database.pool(), crypto.clone())
        .create(&CreatorCredentials::new(
            creator.clone(),
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
    InvoiceStore::new(database.pool(), crypto.clone())
        .create_atomic(AtomicInvoiceInput {
            creator: &creator,
            reader: &reader,
            bundle_binding: b"outbox-bundle",
            lock_resource_binding: b"outbox-lock",
            payment_request_binding: b"outbox-payment-request",
            invoice_payloads: &Payloads {
                reader: reader.clone(),
            },
            proposal_acceptance_seconds: 3600,
            payment_window_seconds: 86400,
        })
        .await
        .unwrap();
    OutboxStore::new(database.pool(), crypto)
}

fn handoff_result() -> HandoffResult {
    HandoffResult::PaymentRequestProposal {
        outbound_message_id: 42,
        event_id: "event-42".into(),
        payment_request_id: "request-42".into(),
    }
}

#[tokio::test]
async fn claim_renewal_keeps_slow_handoff_owned_until_transition() {
    let database = TestDatabase::create().await;
    let outbox = queued_invoice(&database).await;
    let lease = Duration::from_secs(3);
    let claim = outbox
        .claim(Uuid::new_v4(), 1, lease)
        .await
        .unwrap()
        .remove(0);
    let transitioned = with_claim_renewal(&outbox, &claim, lease, async {
        tokio::time::sleep(Duration::from_secs(4)).await;
        assert!(
            outbox
                .claim(Uuid::new_v4(), 1, lease)
                .await
                .unwrap()
                .is_empty()
        );
        outbox
            .mark_handed_off(&claim, &handoff_result())
            .await
            .unwrap()
    })
    .await;
    assert!(transitioned);
    assert!(!outbox.renew_claim(&claim, lease).await.unwrap());
    database.cleanup().await;
}

#[tokio::test]
async fn renewal_loss_finishes_admitted_work_without_reviving_an_old_claim() {
    let database = TestDatabase::create().await;
    let outbox = queued_invoice(&database).await;
    let lease = Duration::from_secs(3);
    let claim = outbox
        .claim(Uuid::new_v4(), 1, lease)
        .await
        .unwrap()
        .remove(0);
    sqlx::query("UPDATE outbox SET lease_expires_at = clock_timestamp() - INTERVAL '1 second' WHERE id = $1")
        .bind(claim.id()).execute(database.pool()).await.unwrap();
    assert!(!outbox.renew_claim(&claim, lease).await.unwrap());
    let replacement = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .remove(0);
    assert_ne!(replacement.claim_token(), claim.claim_token());
    let completed = with_claim_renewal(&outbox, &claim, lease, async {
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(
            !outbox
                .mark_handed_off(&claim, &handoff_result())
                .await
                .unwrap()
        );
        true
    })
    .await;
    assert!(completed);
    assert!(outbox.claim_handoff_eligible(&replacement).await.unwrap());
    assert!(
        outbox
            .mark_handed_off(&replacement, &handoff_result())
            .await
            .unwrap()
    );
    database.cleanup().await;
}

#[tokio::test]
async fn claim_renewal_respects_proposal_generation_fences() {
    let database = TestDatabase::create().await;
    let outbox = queued_invoice(&database).await;
    let lease = Duration::from_secs(30);
    let claim = outbox
        .claim(Uuid::new_v4(), 1, lease)
        .await
        .unwrap()
        .remove(0);
    assert!(outbox.renew_claim(&claim, lease).await.unwrap());
    sqlx::query("UPDATE lock_payment_generations SET current_generation = current_generation + 1")
        .execute(database.pool())
        .await
        .unwrap();
    assert!(!outbox.renew_claim(&claim, lease).await.unwrap());
    assert!(!outbox.claim_handoff_eligible(&claim).await.unwrap());
    database.cleanup().await;
}

#[tokio::test]
async fn pending_links_reset_failure_backoff_without_resetting_attempts() {
    let database = TestDatabase::create().await;
    let outbox = queued_invoice(&database).await;
    let stages = [
        (OutboxRetryClass::RegistryFetch, 1),
        (OutboxRetryClass::ReaderAuthorizationFetch, 2),
        (OutboxRetryClass::LinkPending, 0),
        (OutboxRetryClass::LinkEstablishment, 1),
        (OutboxRetryClass::PaymentRequestProposal, 2),
    ];
    for (index, (stage, expected)) in stages.into_iter().enumerate() {
        let claim = outbox
            .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
            .await
            .unwrap()
            .remove(0);
        assert_eq!(claim.attempt_count(), i32::try_from(index + 1).unwrap());
        assert!(
            outbox
                .mark_retryable(&claim, Duration::ZERO, stage)
                .await
                .unwrap()
        );
        let count: i32 = sqlx::query_scalar("SELECT failure_count FROM outbox WHERE id = $1")
            .bind(claim.id())
            .fetch_one(database.pool())
            .await
            .unwrap();
        assert_eq!(count, expected);
    }
    let claim = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .remove(0);
    assert_eq!(claim.failure_count(), 2);
    assert!(
        outbox
            .mark_handed_off(&claim, &handoff_result())
            .await
            .unwrap()
    );
    database.cleanup().await;
}

async fn build_pubky_testnet() -> EphemeralTestnet {
    let postgres = std::env::var("TEST_DATABASE_URL").unwrap();
    let postgres = pubky_testnet::pubky_homeserver::ConnectionString::new(&postgres).unwrap();
    EphemeralTestnet::builder()
        .postgres(postgres)
        .build()
        .await
        .unwrap()
}

fn creator() -> CreatorPubky {
    parse_creator(CREATOR).unwrap()
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

struct Payloads {
    reader: ReaderPubky,
}

impl InvoicePayloadFactory for Payloads {
    fn for_child_index(&self, child_index: i64) -> Result<InvoicePayloads, PersistenceError> {
        let address = format!("outbox-test-address-{child_index}");
        let base = common::payment_intent(&self.reader, address);
        let mut terms = base.terms().unwrap().clone();
        terms.rates = vec![paykit_lib::ConversionRate {
            asset: "usdt".into(),
            value: "81000".into(),
        }];
        terms
            .accepted_endpoint_identifiers
            .push("usdt-arbitrum-address".into());
        terms.payment_endpoints.insert(
            "usdt-arbitrum-address".into(),
            paykit_server::domain::receiving::UsdtAddress::try_from(
                "0x2222222222222222222222222222222222222222".to_owned(),
            )
            .unwrap()
            .endpoint()
            .to_string(),
        );
        Ok(InvoicePayloads {
            payment_request_intent:
                paykit_server::application::semantic_intent::DeliveryIntentV1::payment_request(
                    self.reader.to_string(),
                    common::app_id(),
                    &terms.to_sdk().unwrap(),
                )
                .unwrap(),
        })
    }
}

struct ReconciliationAdapter {
    statuses: Mutex<VecDeque<OutboundPrivateMessageStatus>>,
}

#[async_trait]
impl Adapter for ReconciliationAdapter {
    async fn fetch_registry(
        &self,
        _reader: &str,
    ) -> Result<Option<PaykitAppRegistry>, HandoffError> {
        Ok(None)
    }

    async fn fetch_authorization(
        &self,
        _reader: &str,
    ) -> Result<paykit_server::application::create_invoice::ReaderAuthorization, HandoffError> {
        Err(HandoffError::Permanent)
    }

    async fn ensure_link_with_peer(&self, _reader: &str) -> Result<(), HandoffError> {
        Err(HandoffError::Permanent)
    }

    async fn propose_payment_request(
        &self,
        _reader: &str,
        _payment_request_id: paykit_lib::PaymentRequestId,
        _terms: &paykit_server::application::semantic_intent::PaymentTermsV1,
    ) -> Result<HandoffResult, HandoffError> {
        Err(HandoffError::Permanent)
    }

    async fn cancel_payment_request(
        &self,
        _reader: &str,
        _payment_request_id: &str,
    ) -> Result<HandoffResult, HandoffError> {
        Err(HandoffError::Permanent)
    }

    async fn outbound_status(
        &self,
        _outbound_message_id: u64,
    ) -> Result<Option<OutboundPrivateMessageStatus>, HandoffError> {
        Ok(self.statuses.lock().unwrap().pop_front())
    }
}

async fn assert_reconciliation_status(
    database: &TestDatabase,
    outbox: &OutboxStore,
    outbound_id: u64,
    sdk_status: Option<OutboundPrivateMessageStatus>,
    expected_status: &str,
    expected_error_class: &str,
) {
    let row_id: Uuid = sqlx::query_scalar(
        "INSERT INTO outbox \
         (creator_id, intent_envelope, intent_kind, status, sdk_outbound_message_id) \
         SELECT id, decode('00', 'hex'), 'endpoint_publication', 'handed_off', $1 \
         FROM creators LIMIT 1 \
         RETURNING id",
    )
    .bind(outbound_id.to_string())
    .fetch_one(database.pool())
    .await
    .unwrap();
    let claims = outbox
        .claim_reconciliation(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap();
    let claim = claims
        .iter()
        .find(|claim| claim.id() == row_id)
        .expect("inserted reconciliation row was claimable");
    let adapter = ReconciliationAdapter {
        statuses: Mutex::new(sdk_status.into_iter().collect()),
    };
    assert!(
        process_reconciliation(outbox, &adapter, claim, Duration::from_secs(5))
            .await
            .unwrap()
    );
    let actual: (String, bool, Option<String>) = sqlx::query_as(
        "SELECT status, next_attempt_at > NOW(), error_class FROM outbox WHERE id = $1",
    )
    .bind(row_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(actual.0, expected_status);
    assert_eq!(actual.2.as_deref(), Some(expected_error_class));
    if expected_status == "handed_off" {
        assert!(actual.1, "retryable SDK status did not receive backoff");
    }
    sqlx::query("DELETE FROM outbox WHERE id = $1")
        .bind(row_id)
        .execute(database.pool())
        .await
        .unwrap();
}

#[tokio::test]
async fn targeted_reconciliation_preserves_other_creators_due_times_and_leases() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[7; 32]).unwrap());
    let creators = CreatorStore::new(database.pool(), crypto.clone());
    let mut creator_ids = Vec::new();
    for creator in [creator(), parse_creator(&reader().to_string()).unwrap()] {
        let stored = creators
            .create(&CreatorCredentials::new(
                creator,
                "session-secret".into(),
                PaykitIdentitySecretKey::new([9; 32], 1).unwrap(),
                None,
                None,
            ))
            .await
            .unwrap();
        creator_ids.push(stored.id());
    }
    let outbox = OutboxStore::new(database.pool(), crypto);
    let mut row_ids = Vec::new();
    for creator_id in [
        creator_ids[0],
        creator_ids[0],
        creator_ids[0],
        creator_ids[1],
    ] {
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO outbox \
             (creator_id, intent_envelope, intent_kind, status, sdk_outbound_message_id) \
             VALUES ($1, decode('00', 'hex'), 'endpoint_publication', 'handed_off', '1') \
             RETURNING id",
        )
        .bind(creator_id)
        .fetch_one(database.pool())
        .await
        .unwrap();
        row_ids.push(id);
    }
    sqlx::query("UPDATE outbox SET next_attempt_at = NOW() + INTERVAL '1 hour' WHERE id = $1")
        .bind(row_ids[1])
        .execute(database.pool())
        .await
        .unwrap();
    let claim_token = Uuid::new_v4();
    sqlx::query(
        "UPDATE outbox SET lease_owner = $2, claim_token = $3, \
         lease_expires_at = NOW() + INTERVAL '1 hour' WHERE id = $1",
    )
    .bind(row_ids[2])
    .bind(Uuid::new_v4())
    .bind(claim_token)
    .execute(database.pool())
    .await
    .unwrap();

    let selected = outbox
        .claim_reconciliation_for_creators(
            Uuid::new_v4(),
            10,
            Duration::from_secs(30),
            Some(&creator_ids[..1]),
        )
        .await
        .unwrap();
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].id(), row_ids[0]);
    assert_eq!(selected[0].creator_id(), creator_ids[0]);
    assert!(
        outbox
            .claim_reconciliation_for_creators(
                Uuid::new_v4(),
                10,
                Duration::from_secs(30),
                Some(&[]),
            )
            .await
            .unwrap()
            .is_empty()
    );

    // A fresh worker's periodic scan still recovers work without an in-memory hint.
    let restarted = OutboxStore::new(
        database.pool(),
        Arc::new(Crypto::from_master_key(&[7; 32]).unwrap()),
    );
    let periodic = restarted
        .claim_reconciliation(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(periodic.len(), 1);
    assert_eq!(periodic[0].id(), row_ids[3]);
    let retained_token: Uuid = sqlx::query_scalar("SELECT claim_token FROM outbox WHERE id = $1")
        .bind(row_ids[2])
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(retained_token, claim_token);
    database.cleanup().await;
}

#[tokio::test]
async fn invoice_request_is_claimable_directly_and_preserves_delivery_fences() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[7; 32]).unwrap());
    let creator = creator();
    let reader = reader();
    CreatorStore::new(database.pool(), crypto.clone())
        .create(&CreatorCredentials::new(
            creator.clone(),
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
    let payloads = Payloads {
        reader: reader.clone(),
    };
    let invoice = InvoiceStore::new(database.pool(), crypto.clone())
        .create_atomic(AtomicInvoiceInput {
            creator: &creator,
            reader: &reader,
            bundle_binding: b"outbox-bundle",
            lock_resource_binding: b"outbox-lock",
            payment_request_binding: b"outbox-payment-request",
            invoice_payloads: &payloads,

            proposal_acceptance_seconds: 60 * 60,
            payment_window_seconds: 24 * 60 * 60,
        })
        .await
        .unwrap();
    let outbox = OutboxStore::new(database.pool(), crypto);

    let request_claims = outbox
        .claim(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(request_claims.len(), 1);
    assert_eq!(request_claims[0].id(), invoice.payment_request_outbox_id());
    assert_eq!(
        outbox
            .delivery_intent(&request_claims[0])
            .unwrap()
            .terms()
            .unwrap()
            .payment_endpoints
            .len(),
        2
    );
    let retry_adapter = ReconciliationAdapter {
        statuses: Mutex::new(VecDeque::new()),
    };
    assert!(
        process_claim(
            &outbox,
            &retry_adapter,
            &request_claims[0],
            Duration::from_secs(5),
        )
        .await
        .unwrap()
    );
    let retry_state: (String, bool, Option<String>) = sqlx::query_as(
        "SELECT status, next_attempt_at > NOW(), error_class FROM outbox WHERE id = $1",
    )
    .bind(request_claims[0].id())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(
        retry_state,
        ("retryable".into(), true, Some("registry_missing".into()))
    );
    sqlx::query("UPDATE outbox SET next_attempt_at = NOW() WHERE id = $1")
        .bind(request_claims[0].id())
        .execute(database.pool())
        .await
        .unwrap();
    let request_claims = outbox
        .claim(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(request_claims.len(), 1);
    assert!(
        !outbox.delivery_available().await.unwrap(),
        "leasing a retry must not report recovery"
    );
    sqlx::query("UPDATE outbox SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1")
        .bind(request_claims[0].id())
        .execute(database.pool())
        .await
        .unwrap();
    let reclaimed_request = outbox
        .claim(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(reclaimed_request.len(), 1);
    assert!(
        !outbox
            .mark_handed_off(
                &request_claims[0],
                &HandoffResult::PaymentRequestProposal {
                    outbound_message_id: 16,
                    event_id: "event-16".into(),
                    payment_request_id: "request-16".into(),
                },
            )
            .await
            .unwrap(),
        "an expired fence overwrote reclaimed work"
    );
    assert!(
        tokio::time::timeout(Duration::ZERO, outbox.wait_for_transport())
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::ZERO, outbox.wait_for_reconciliation())
            .await
            .is_err()
    );
    assert!(
        outbox
            .mark_handed_off(
                &reclaimed_request[0],
                &HandoffResult::PaymentRequestProposal {
                    outbound_message_id: 17,
                    event_id: "event-17".into(),
                    payment_request_id: "request-17".into(),
                },
            )
            .await
            .unwrap()
    );
    let worker_outbox = outbox.clone();
    assert_eq!(
        tokio::time::timeout(Duration::ZERO, worker_outbox.wait_for_transport())
            .await
            .unwrap(),
        vec![reclaimed_request[0].creator_id()]
    );
    assert_eq!(
        tokio::time::timeout(Duration::ZERO, worker_outbox.wait_for_reconciliation())
            .await
            .unwrap(),
        vec![reclaimed_request[0].creator_id()]
    );
    assert!(
        outbox
            .claim(Uuid::new_v4(), 10, Duration::from_secs(30))
            .await
            .unwrap()
            .is_empty(),
        "handed-off work must not be enqueued again"
    );
    let reconciliation = outbox
        .claim_reconciliation(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(reconciliation.len(), 1);
    assert_eq!(reconciliation[0].sdk_outbound_message_id().unwrap(), 17);
    let reconciliation_adapter = ReconciliationAdapter {
        statuses: Mutex::new(VecDeque::from([OutboundPrivateMessageStatus::Pending])),
    };
    assert!(
        process_reconciliation(
            &outbox,
            &reconciliation_adapter,
            &reconciliation[0],
            Duration::ZERO,
        )
        .await
        .unwrap()
    );
    assert!(
        outbox
            .claim(Uuid::new_v4(), 10, Duration::from_secs(30))
            .await
            .unwrap()
            .is_empty(),
        "Pending SDK state caused another enqueue"
    );
    let payment_claims = reclaimed_request;
    assert_eq!(payment_claims.len(), 1);
    assert_eq!(payment_claims[0].id(), invoice.payment_request_outbox_id());
    assert_eq!(
        outbox
            .delivery_intent(&payment_claims[0])
            .unwrap()
            .terms()
            .unwrap()
            .payment_endpoints
            .len(),
        2
    );
    let ids: (String, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT sdk_outbound_message_id, sdk_event_id, sdk_payment_request_id FROM outbox WHERE id = $1",
    )
    .bind(payment_claims[0].id())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(
        ids,
        (
            "17".into(),
            Some("event-17".into()),
            Some("request-17".into())
        )
    );

    let failed_reconciliation = outbox
        .claim_reconciliation(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(failed_reconciliation.len(), 1);
    let failed_adapter = ReconciliationAdapter {
        statuses: Mutex::new(VecDeque::from([OutboundPrivateMessageStatus::Failed])),
    };
    assert!(
        process_reconciliation(
            &outbox,
            &failed_adapter,
            &failed_reconciliation[0],
            Duration::from_secs(5),
        )
        .await
        .unwrap()
    );
    let failed_status: (String, bool) =
        sqlx::query_as("SELECT status, next_attempt_at > NOW() FROM outbox WHERE id = $1")
            .bind(payment_claims[0].id())
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(failed_status, ("handed_off".into(), true));
    sqlx::query("UPDATE outbox SET next_attempt_at = NOW() WHERE id = $1")
        .bind(payment_claims[0].id())
        .execute(database.pool())
        .await
        .unwrap();
    let sent_reconciliation = outbox
        .claim_reconciliation(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(sent_reconciliation.len(), 1);
    let sent_adapter = ReconciliationAdapter {
        statuses: Mutex::new(VecDeque::from([OutboundPrivateMessageStatus::Sent])),
    };
    assert!(
        process_reconciliation(
            &outbox,
            &sent_adapter,
            &sent_reconciliation[0],
            Duration::from_secs(5),
        )
        .await
        .unwrap()
    );
    let sent_status: String = sqlx::query_scalar("SELECT status FROM outbox WHERE id = $1")
        .bind(payment_claims[0].id())
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(sent_status, "delivered");

    for (offset, status) in [
        OutboundPrivateMessageStatus::Pending,
        OutboundPrivateMessageStatus::Sending,
    ]
    .into_iter()
    .enumerate()
    {
        assert_reconciliation_status(
            &database,
            &outbox,
            100 + offset as u64,
            Some(status),
            "handed_off",
            "reconciliation_pending",
        )
        .await;
    }
    for (offset, status) in [
        OutboundPrivateMessageStatus::Invalid,
        OutboundPrivateMessageStatus::RecoveryRequired,
        OutboundPrivateMessageStatus::Superseded,
    ]
    .into_iter()
    .enumerate()
    {
        assert_reconciliation_status(
            &database,
            &outbox,
            200 + offset as u64,
            Some(status),
            "permanently_failed",
            "permanent_sdk_reconciliation",
        )
        .await;
    }

    assert_reconciliation_status(
        &database,
        &outbox,
        300,
        None,
        "permanently_failed",
        "permanent_sdk_reconciliation",
    )
    .await;

    let corrupt_id: Uuid = sqlx::query_scalar(
        "INSERT INTO outbox (creator_id, intent_envelope, intent_kind, status) \
         SELECT id, decode('00', 'hex'), 'endpoint_publication', 'queued' \
         FROM creators LIMIT 1 RETURNING id",
    )
    .fetch_one(database.pool())
    .await
    .unwrap();
    let corrupt_claim = outbox
        .claim(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(corrupt_claim.len(), 1);
    assert_eq!(corrupt_claim[0].id(), corrupt_id);
    assert!(
        process_claim(
            &outbox,
            &retry_adapter,
            &corrupt_claim[0],
            Duration::from_secs(5),
        )
        .await
        .unwrap()
    );
    let corrupt_status: (String, Option<String>) =
        sqlx::query_as("SELECT status, error_class FROM outbox WHERE id = $1")
            .bind(corrupt_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(
        corrupt_status,
        ("permanently_failed".into(), Some("permanent".into()))
    );

    let missing_intent_insert = sqlx::query(
        "INSERT INTO outbox (creator_id, intent_kind, status) \
         SELECT id, 'endpoint_publication', 'queued' FROM creators LIMIT 1",
    )
    .execute(database.pool())
    .await;
    assert!(
        missing_intent_insert.is_err(),
        "schema accepted a claimable row without an intent"
    );
    let unattributed_handoff = sqlx::query(
        "INSERT INTO outbox (creator_id, intent_envelope, intent_kind, status) \
         SELECT id, decode('00', 'hex'), 'endpoint_publication', 'handed_off' \
         FROM creators LIMIT 1",
    )
    .execute(database.pool())
    .await;
    assert!(
        unattributed_handoff.is_err(),
        "schema accepted handed_off without an SDK outbound ID"
    );
    let unpaired_payment_ids = sqlx::query(
        "INSERT INTO outbox \
         (creator_id, intent_envelope, intent_kind, status, sdk_event_id) \
         SELECT id, decode('00', 'hex'), 'endpoint_publication', 'queued', 'event-only' \
         FROM creators LIMIT 1",
    )
    .execute(database.pool())
    .await;
    assert!(
        unpaired_payment_ids.is_err(),
        "schema accepted an unpaired SDK Event ID"
    );

    database.cleanup().await;
}

#[tokio::test]
async fn enqueue_retry_preserves_500ms_deadline_across_store_recreation() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[7; 32]).unwrap());
    let creator = creator();
    let reader = reader();
    CreatorStore::new(database.pool(), crypto.clone())
        .create(&CreatorCredentials::new(
            creator.clone(),
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
    let invoice = InvoiceStore::new(database.pool(), crypto.clone())
        .create_atomic(AtomicInvoiceInput {
            creator: &creator,
            reader: &reader,
            bundle_binding: b"subsecond-retry-bundle",
            lock_resource_binding: b"subsecond-retry-lock",
            payment_request_binding: b"subsecond-retry-request",
            invoice_payloads: &Payloads {
                reader: reader.clone(),
            },
            proposal_acceptance_seconds: 60 * 60,
            payment_window_seconds: 24 * 60 * 60,
        })
        .await
        .unwrap();
    sqlx::query("UPDATE outbox SET failure_count = 2 WHERE id = $1")
        .bind(invoice.payment_request_outbox_id())
        .execute(database.pool())
        .await
        .unwrap();
    let outbox = OutboxStore::new(database.pool(), crypto.clone());
    let claim = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(claim.id(), invoice.payment_request_outbox_id());
    assert_eq!(claim.failure_count(), 2);
    assert!(
        outbox
            .mark_retryable(
                &claim,
                Duration::from_millis(500),
                OutboxRetryClass::LinkPending,
            )
            .await
            .unwrap()
    );

    let (persisted_delay_ms, failure_count): (i64, i32) = sqlx::query_as(
        "SELECT ROUND(EXTRACT(EPOCH FROM (next_attempt_at - updated_at)) * 1000)::BIGINT, failure_count \
         FROM outbox WHERE id = $1",
    )
    .bind(claim.id())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(persisted_delay_ms, 500);
    assert_eq!(failure_count, 0);
    sqlx::query(
        "UPDATE outbox \
         SET updated_at = updated_at + INTERVAL '1 minute', \
             next_attempt_at = next_attempt_at + INTERVAL '1 minute' \
         WHERE id = $1",
    )
    .bind(claim.id())
    .execute(database.pool())
    .await
    .unwrap();

    drop(outbox);
    let restarted_pool = sqlx::PgPool::connect(database.database_url())
        .await
        .unwrap();
    let restarted_outbox = OutboxStore::new(&restarted_pool, crypto);
    assert!(
        restarted_outbox
            .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
            .await
            .unwrap()
            .is_empty(),
        "persisted 500ms retry became immediately claimable after restart"
    );
    sqlx::query(
        "UPDATE outbox \
         SET updated_at = updated_at - INTERVAL '2 minutes', \
             next_attempt_at = next_attempt_at - INTERVAL '2 minutes' \
         WHERE id = $1",
    )
    .bind(claim.id())
    .execute(&restarted_pool)
    .await
    .unwrap();
    let retried = restarted_outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(retried.len(), 1);
    assert_eq!(retried[0].id(), claim.id());
    assert_eq!(retried[0].failure_count(), 0);
    assert_eq!(retried[0].attempt_count(), claim.attempt_count() + 1);
    drop(restarted_outbox);
    restarted_pool.close().await;
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_sdk_payment_request_retry_preserves_ids_and_only_active_claim_associates() {
    Box::pin(assert_public_sdk_handoff(true)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn responder_sdk_handoff_preserves_targeted_delivery() {
    Box::pin(assert_public_sdk_handoff(false)).await;
}

async fn assert_public_sdk_handoff(creator_initiates: bool) {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let testnet = build_pubky_testnet().await;
    let crypto = Arc::new(Crypto::from_master_key(&[11; 32]).unwrap());
    let homeserver = PubkyPublicKey::from_public_key(&testnet.homeserver_app().public_key());
    let bootstrap =
        PubkySessionBootstrap::with_pubky(testnet.sdk().unwrap(), "app.paykit.server").unwrap();

    let creator_keypair = Keypair::random();
    let creator_bootstrap = bootstrap
        .sign_up(
            &PubkyLocalSecretKey::new(creator_keypair.secret_key()),
            &homeserver,
            None,
            paykit_sdk::PAYKIT_AUTHORIZER_SESSION_CAPABILITIES,
        )
        .await
        .unwrap();
    // Persist only the ordinary delegated grant, not the owner's authorizer scope.
    let creator_grant = bootstrap
        .sign_in(
            &PubkyLocalSecretKey::new(creator_keypair.secret_key()),
            paykit_sdk::PAYKIT_SESSION_CAPABILITIES,
        )
        .await
        .unwrap();
    let creator_session_secret = creator_grant
        .export_session_secret()
        .await
        .unwrap()
        .into_inner();
    let creator = parse_creator(&format!("pubky{}", creator_bootstrap.public_key)).unwrap();
    let creator_record = CreatorStore::new(database.pool(), crypto.clone())
        .create(&CreatorCredentials::new(
            creator.clone(),
            creator_session_secret,
            PubkyLocalSecretKey::new(creator_keypair.secret_key())
                .derive_paykit_identity_secret_key(1)
                .unwrap(),
            Some(paykit_server::domain::receiving::BitcoinAccount {
                xpub: "unused-test-xpub".to_owned().into(),
                account_index: 0,
            }),
            None,
        ))
        .await
        .unwrap();
    let creator_sdk =
        sdk_fixtures::hosted_sdk(creator_bootstrap.access.clone(), "paykit-server", 0).await;

    let peer_keypair = Keypair::random();
    let peer_bootstrap = bootstrap
        .sign_up(
            &PubkyLocalSecretKey::new(peer_keypair.secret_key()),
            &homeserver,
            None,
            paykit_sdk::PAYKIT_AUTHORIZER_SESSION_CAPABILITIES,
        )
        .await
        .unwrap();
    let peer_sdk = sdk_fixtures::hosted_sdk(peer_bootstrap.access.clone(), "bitkit", 0).await;

    if creator_initiates {
        creator_sdk
            .initiate_link_with_peer(peer_bootstrap.public_key.clone())
            .await
            .unwrap();
        peer_sdk
            .accept_link_with_peer(creator_bootstrap.public_key.clone())
            .await
            .unwrap();
    } else {
        peer_sdk
            .initiate_link_with_peer(creator_bootstrap.public_key.clone())
            .await
            .unwrap();
        creator_sdk
            .accept_link_with_peer(peer_bootstrap.public_key.clone())
            .await
            .unwrap();
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut creator_link = LinkedPeerState::Linking;
    let mut peer_link = LinkedPeerState::Linking;
    while creator_link != LinkedPeerState::Linked || peer_link != LinkedPeerState::Linked {
        assert!(tokio::time::Instant::now() < deadline, "link timed out");
        if creator_link != LinkedPeerState::Linked {
            creator_link = creator_sdk
                .advance_link_handshake(peer_bootstrap.public_key.clone())
                .await
                .unwrap()
                .state;
        }
        if peer_link != LinkedPeerState::Linked {
            peer_link = peer_sdk
                .advance_link_handshake(creator_bootstrap.public_key.clone())
                .await
                .unwrap()
                .state;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let reader = parse_reader(&format!("pubky{}", peer_bootstrap.public_key)).unwrap();
    let invoice = InvoiceStore::new(database.pool(), crypto.clone())
        .create_atomic(AtomicInvoiceInput {
            creator: &creator,
            reader: &reader,
            bundle_binding: b"public-sdk-crash-window-bundle",
            lock_resource_binding: b"public-sdk-crash-window-lock",
            payment_request_binding: b"public-sdk-crash-window-request",
            invoice_payloads: &Payloads {
                reader: reader.clone(),
            },

            proposal_acceptance_seconds: 60 * 60,
            payment_window_seconds: 24 * 60 * 60,
        })
        .await
        .unwrap();
    let outbox = OutboxStore::new(database.pool(), crypto.clone());
    let first_claim = outbox
        .claim(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(first_claim.id(), invoice.payment_request_outbox_id());
    let intent = outbox.delivery_intent(&first_claim).unwrap();
    let creators = CreatorStore::new(database.pool(), crypto.clone());
    let config = PaykitConfig {
        client_id: pubky::ClientId::new("app.paykit.server").unwrap(),
        app_id: common::app_id(),
        network: PaykitNetwork::Testnet,
        proposal_acceptance_window: Duration::from_secs(60 * 60),
        payment_window: Duration::from_secs(24 * 60 * 60),
        conversion_payment_window: std::time::Duration::from_secs(3600),
    };
    let sessions = CreatorSessions::new(creators.clone(), testnet.sdk().unwrap(), config.clone());
    let provider = sessions.provider(&creator);
    let storage = paykit_sdk::PubkySharedStateStorage::new(provider.clone());
    let adapter = PaykitAdapter::new(creator_record.id(), provider.clone(), &config).unwrap();
    let first_result = with_claim_renewal(&outbox, &first_claim, Duration::from_secs(30), async {
        adapter
            .execute_claimed_handoff(&outbox, &first_claim, &intent)
            .await
            .unwrap()
    })
    .await;
    let unassociated: (Option<String>, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT sdk_outbound_message_id, sdk_event_id, sdk_payment_request_id FROM outbox WHERE id = $1",
    )
    .bind(first_claim.id())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(unassociated, (None, None, None));
    // Lose the adapter after the SDK commit, before recording its IDs in PostgreSQL.
    drop(adapter);

    sqlx::query("UPDATE outbox SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1")
        .bind(first_claim.id())
        .execute(database.pool())
        .await
        .unwrap();
    let second_claim = outbox
        .claim(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(second_claim.id(), first_claim.id());
    let adapter = PaykitAdapter::new(creator_record.id(), provider.clone(), &config).unwrap();
    let second_result =
        with_claim_renewal(&outbox, &second_claim, Duration::from_secs(30), async {
            let retry_intent = outbox.delivery_intent(&second_claim).unwrap();
            let result = adapter
                .execute_claimed_handoff(&outbox, &second_claim, &retry_intent)
                .await
                .unwrap();
            assert!(
                !outbox
                    .mark_handed_off(&first_claim, &first_result)
                    .await
                    .unwrap()
            );
            assert!(
                outbox
                    .mark_handed_off(&second_claim, &result)
                    .await
                    .unwrap()
            );
            result
        })
        .await;

    let HandoffResult::PaymentRequestProposal {
        outbound_message_id: first_outbound,
        event_id: first_event,
        payment_request_id: first_request,
    } = &first_result
    else {
        unreachable!()
    };
    let HandoffResult::PaymentRequestProposal {
        outbound_message_id: second_outbound,
        event_id: second_event,
        payment_request_id: second_request,
    } = &second_result
    else {
        unreachable!()
    };
    assert_eq!(first_outbound, second_outbound);
    assert_eq!(first_event, second_event);
    assert_eq!(first_request, second_request);
    assert_eq!(first_request, &first_claim.id().to_string());

    let durable_state = creator_sdk.export_backup_state().await.unwrap();
    let proposals = durable_state
        .outbound_private_messages
        .iter()
        .filter(|record| record.kind == "paykit.payment_request")
        .collect::<Vec<_>>();
    assert_eq!(proposals.len(), 1);
    let outbound = proposals[0];
    assert_eq!(outbound.outbound_message_id, *first_outbound);
    assert!(outbound.raw_json.len() <= paykit_lib::pubky_noise::snow_crypto::PUBKY_NOISE_MSG_LEN);
    let wire: serde_json::Value = serde_json::from_str(&outbound.raw_json).unwrap();
    assert_eq!(wire["event_id"], first_event.as_str());
    assert_eq!(wire["payment_request_id"], first_request.as_str());
    assert!(wire["request"]["payment_endpoints"].is_object());

    let old_list = creator_sdk
        .enqueue_private_payment_list_with_receiving_details(
            peer_bootstrap.public_key.clone(),
            vec![paykit_sdk::PrivateReceivingDetail {
                identifier: "btc-bitcoin-p2wpkh".into(),
                payload: serde_json::json!({"value": "unrelated-old-address"}).to_string(),
            }],
        )
        .await
        .unwrap();
    creator_sdk
        .enqueue_private_payment_list_with_receiving_details(
            peer_bootstrap.public_key.clone(),
            vec![paykit_sdk::PrivateReceivingDetail {
                identifier: "btc-bitcoin-p2wpkh".into(),
                payload: serde_json::json!({"value": "unrelated-new-address"}).to_string(),
            }],
        )
        .await
        .unwrap();
    // This inactive peer has valid key authorization but no App Registry or receive
    // snapshot. Its intake failure must not block the healthy peer's sends.
    let missing_registry_peer = bootstrap
        .sign_up(
            &PubkyLocalSecretKey::new(Keypair::random().secret_key()),
            &homeserver,
            None,
            paykit_sdk::PAYKIT_AUTHORIZER_SESSION_CAPABILITIES,
        )
        .await
        .unwrap();
    let missing_registry_provider =
        sdk_fixtures::TestSessionProvider::new(missing_registry_peer.access);
    let missing_registry_sdk = paykit_sdk::PaykitSdk::new(
        paykit_sdk::PubkySharedStateStorage::new(missing_registry_provider.clone()),
        missing_registry_provider,
        sdk_fixtures::TestPaymentAdapter,
        paykit_sdk::PaykitSdkConfig::new("bitkit").unwrap(),
    );
    missing_registry_sdk.initialize().await.unwrap();
    let missing_registry_authorization = missing_registry_sdk
        .publish_paykit_noise_key_authorization()
        .await
        .unwrap();
    assert!(
        missing_registry_sdk
            .paykit_app_registry(missing_registry_peer.public_key.clone())
            .await
            .unwrap()
            .is_none()
    );
    let lease = storage
        .transaction(|tx| {
            let now = sqlx::types::chrono::Utc::now();
            Ok(tx
                .claim_peer_link_operation(
                    &peer_bootstrap.public_key,
                    now,
                    now + Duration::from_secs(60),
                )?
                .unwrap())
        })
        .await
        .unwrap();
    assert!(
        adapter
            .maintain_transport()
            .await
            .unwrap_err()
            .is_concurrent_update()
    );
    storage
        .transaction(|tx| {
            assert_eq!(
                tx.peer_link_operation_lease(&peer_bootstrap.public_key),
                Some(lease.clone())
            );
            let outbound = tx.outbound_private_messages(&peer_bootstrap.public_key);
            assert_eq!(
                outbound
                    .iter()
                    .find(|record| record.outbound_message_id == *first_outbound)
                    .unwrap()
                    .status,
                OutboundPrivateMessageStatus::Pending
            );
            tx.release_peer_link_operation(&peer_bootstrap.public_key, lease.lease_id);
            Ok(())
        })
        .await
        .unwrap();
    storage
        .transaction(|tx| {
            let mut linked_peer = tx.linked_peer(&peer_bootstrap.public_key).unwrap();
            linked_peer.counterparty = missing_registry_peer.public_key.clone();
            linked_peer.noise_key_authorization = Some(missing_registry_authorization.clone());
            tx.save_linked_peer(linked_peer);
            Ok(())
        })
        .await
        .unwrap();
    assert!(matches!(
        adapter.maintain_transport().await,
        Err(paykit_sdk::PaykitSdkError::Transport { .. })
    ));
    // Use the process-shared provider after it restores the stored grant.
    let creator_sdk = paykit_sdk::PaykitSdk::new(
        storage.clone(),
        provider,
        sdk_fixtures::TestPaymentAdapter,
        paykit_sdk::PaykitSdkConfig::new("paykit-server").unwrap(),
    );
    let compacted = creator_sdk.export_backup_state().await.unwrap();
    assert!(
        !compacted
            .outbound_private_messages
            .iter()
            .any(|record| record.outbound_message_id == old_list.outbound_message_id)
    );
    assert!(
        compacted
            .outbound_private_messages
            .iter()
            .any(|record| record.outbound_message_id == *first_outbound
                && record.status == OutboundPrivateMessageStatus::Sent)
    );
    peer_sdk
        .receive_private_messages(creator_bootstrap.public_key.clone())
        .await
        .unwrap();
    let received = peer_sdk
        .actionable_received_payment_requests()
        .await
        .unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].payment_request_id, *first_request);
    assert_eq!(received[0].proposal_event_id.as_ref(), Some(first_event));
    for request in received {
        let resolution = peer_sdk
            .resolve_private_payment_request(
                creator_bootstrap.public_key.clone(),
                &paykit_lib::PaymentRequestId::new(request.payment_request_id).unwrap(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            resolution.status,
            paykit_sdk::PrivatePaymentResolutionStatus::Payable
        );
        assert_eq!(resolution.private_payment_list_version, None);
        assert_eq!(resolution.payable_endpoints.len(), 2);
        for endpoint in resolution.payable_endpoints {
            assert!(
                intent
                    .terms()
                    .unwrap()
                    .payment_endpoints
                    .values()
                    .any(|payload| payload == &endpoint.target.payload)
            );
        }
        assert_eq!(
            request.terms.unwrap().conversion,
            Some(paykit_lib::PaymentConversion::Fixed {
                rates: intent.terms().unwrap().rates.clone()
            })
        );
    }

    let associated: (String, String, String) = sqlx::query_as(
        "SELECT sdk_outbound_message_id, sdk_event_id, sdk_payment_request_id \
         FROM outbox WHERE id = $1",
    )
    .bind(second_claim.id())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(
        associated,
        (
            second_outbound.to_string(),
            second_event.clone(),
            second_request.clone(),
        )
    );

    InvoiceStore::new(database.pool(), crypto.clone())
        .create_atomic(AtomicInvoiceInput {
            creator: &creator,
            reader: &reader,
            bundle_binding: b"targeted-handoff",
            lock_resource_binding: b"targeted-handoff",
            payment_request_binding: b"targeted-handoff",
            invoice_payloads: &Payloads {
                reader: reader.clone(),
            },
            proposal_acceptance_seconds: 3600,
            payment_window_seconds: 86400,
        })
        .await
        .unwrap();
    let claim = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    let (outbound_id, request_count, before) =
        with_claim_renewal(&outbox, &claim, Duration::from_secs(30), async {
            let intent = outbox.delivery_intent(&claim).unwrap();
            let result = adapter
                .execute_claimed_handoff(&outbox, &claim, &intent)
                .await
                .unwrap();
            let outbound_id = result.outbound_message_id();
            adapter.send_handed_off(&outbox, &claim).await.unwrap();
            let request_count = creator_sdk.payment_requests().await.unwrap().len();
            let before = creator_sdk.export_backup_state().await.unwrap();
            assert_eq!(
                before
                    .outbound_private_messages
                    .iter()
                    .find(|record| record.outbound_message_id == outbound_id)
                    .unwrap()
                    .status,
                OutboundPrivateMessageStatus::Pending
            );
            assert!(outbox.mark_handed_off(&claim, &result).await.unwrap());
            (outbound_id, request_count, before)
        })
        .await;
    let lease = storage
        .transaction(|tx| {
            let now = sqlx::types::chrono::Utc::now();
            Ok(tx
                .claim_peer_link_operation(
                    &peer_bootstrap.public_key,
                    now,
                    now + Duration::from_secs(60),
                )?
                .unwrap())
        })
        .await
        .unwrap();
    assert!(matches!(
        adapter.send_handed_off(&outbox, &claim).await,
        Err(HandoffError::Retryable(_))
    ));
    assert!(outbox.handoff_is_committed(&claim).await.unwrap());
    storage
        .transaction(|tx| {
            tx.release_peer_link_operation(&peer_bootstrap.public_key, lease.lease_id);
            Ok(())
        })
        .await
        .unwrap();

    // The unrelated Reader's failed intake cannot block this Reader's send.
    // Repeated passes cannot create another proposal or outbound queue record.
    for _ in 0..2 {
        adapter.send_handed_off(&outbox, &claim).await.unwrap();
    }
    let after = creator_sdk.export_backup_state().await.unwrap();
    assert_eq!(
        creator_sdk.payment_requests().await.unwrap().len(),
        request_count
    );
    assert_eq!(
        after.outbound_private_messages.len(),
        before.outbound_private_messages.len()
    );
    assert_eq!(
        after
            .outbound_private_messages
            .iter()
            .find(|record| record.outbound_message_id == outbound_id)
            .unwrap()
            .status,
        OutboundPrivateMessageStatus::Sent
    );
    let status: String = sqlx::query_scalar("SELECT status FROM outbox WHERE id = $1")
        .bind(claim.id())
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(status, "handed_off");

    drop(testnet);
    database.cleanup().await;
}
