use std::{str::FromStr, sync::Arc, time::Duration};

use async_trait::async_trait;
use bitcoin::{OutPoint, Txid};
use paykit_sdk::PaykitIdentitySecretKey;
use paykit_server::{
    application::marketplace_status::{
        MarketplaceBitcoinStatus, MarketplaceInvoiceStatus, MarketplaceStatusError,
        MarketplaceStatusPersistence, MarketplaceStatusService,
    },
    bitcoin::{ObservationTarget, ObservedOutput},
    config::BitcoinNetwork,
    crypto::Crypto,
    domain::locks::{CreatorPubky, ReaderPubky, parse_creator, parse_reader},
    persistence::{
        CreatorCredentials, CreatorStore, MarketplaceActivationInput, MarketplacePreparationInput,
        MarketplacePreparationPayloadFactory, MarketplacePreparationPayloads,
        MarketplacePreparationStore, PersistenceError, run_migrations,
    },
    workers::observer::{ElectrumPort, ObserverError, observe_marketplace_once_at},
};
use paykit_server_e2e::postgres::TestDatabase;
use time::OffsetDateTime;

mod common;

const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";
const ADDRESS: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
const REFERENCE: &str = "7cceb26d-9042-4ea6-bfcb-01bbd778d76e";

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

fn crypto() -> Arc<Crypto> {
    Arc::new(Crypto::from_master_key(&[7; 32]).unwrap())
}

struct Payloads;

impl MarketplacePreparationPayloadFactory for Payloads {
    fn for_child_index(
        &self,
        _child_index: i64,
    ) -> Result<MarketplacePreparationPayloads, PersistenceError> {
        Ok(MarketplacePreparationPayloads {
            payment_request_intent: common::payment_intent_with_reference(
                &reader(),
                ADDRESS.into(),
                REFERENCE.into(),
            ),
        })
    }
}

async fn store(database: &TestDatabase) -> MarketplacePreparationStore {
    run_migrations(database.pool()).await.unwrap();
    CreatorStore::new(database.pool(), crypto())
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
    MarketplacePreparationStore::new(database.pool(), crypto())
}

async fn prepare(
    store: &MarketplacePreparationStore,
) -> paykit_server::persistence::MarketplacePreparationResult {
    prepare_with_window(store, 24 * 60 * 60).await
}

async fn prepare_with_window(
    store: &MarketplacePreparationStore,
    payment_window_seconds: u64,
) -> paykit_server::persistence::MarketplacePreparationResult {
    store
        .prepare(MarketplacePreparationInput {
            creator: &creator(),
            reader: &reader(),
            reference: REFERENCE,
            operation_id: "marketplace-payment:order-1:attempt-1",
            request_binding: b"request-one",
            total_sats: 100,
            payment_window_seconds,
            prepare_ttl_seconds: 15 * 60,
            payloads: &Payloads,
        })
        .await
        .unwrap()
}

async fn insert_lifecycle(database: &TestDatabase, invoice_id: uuid::Uuid, state: &str) {
    sqlx::query(
        "INSERT INTO payment_request_lifecycles (
             marketplace_preparation_id, sdk_payment_request_id, request_state,
             state_event_id, last_stream_item_id, last_event_at
         ) VALUES ($1, $2, $3, $4, 1, clock_timestamp())",
    )
    .bind(invoice_id)
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(state)
    .bind(uuid::Uuid::new_v4().to_string())
    .execute(database.pool())
    .await
    .unwrap();
}

struct FixedBatch(Vec<ObservedOutput>);

#[async_trait]
impl ElectrumPort for FixedBatch {
    async fn observations(
        &self,
        _targets: &[ObservationTarget],
    ) -> Result<Vec<ObservedOutput>, ObserverError> {
        Ok(self.0.clone())
    }
}

fn outpoint(byte: u8) -> OutPoint {
    OutPoint::new(
        Txid::from_str(&format!("{byte:02x}{}", "00".repeat(31))).unwrap(),
        u32::from(byte),
    )
}

#[tokio::test]
async fn status_scopes_owner_and_projects_publication_and_resolution() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let prepared = prepare(&store).await;
    let invoice_id = prepared.invoice_id();

    assert_eq!(
        store.status(&creator(), invoice_id).await.unwrap(),
        Some(MarketplaceInvoiceStatus::inactive(
            invoice_id, "prepared", None, None,
        ))
    );
    assert_eq!(
        store.status(&other_creator(), invoice_id).await.unwrap(),
        None
    );
    assert_eq!(
        store
            .status(&creator(), uuid::Uuid::new_v4())
            .await
            .unwrap(),
        None
    );

    let activated = store
        .activate(MarketplaceActivationInput {
            creator: &creator(),
            invoice_id,
            total_sats: 100,
            proposal_acceptance_window: Duration::from_secs(30 * 60),
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        store.status(&creator(), invoice_id).await.unwrap(),
        Some(MarketplaceInvoiceStatus::active(
            invoice_id,
            "pending",
            None,
            "undetected",
            activated.activated_at(),
            activated.payment_deadline(),
            None,
            None,
            None,
        ))
    );

    for (stored, projected) in [
        ("handed_off", "pending"),
        ("delivered", "delivered"),
        ("permanently_failed", "failed"),
    ] {
        sqlx::query(
            "UPDATE outbox SET status = $1,
                    sdk_outbound_message_id = CASE
                        WHEN $1 IN ('handed_off', 'delivered') THEN '1'
                        ELSE sdk_outbound_message_id
                    END
             WHERE marketplace_preparation_id = $2",
        )
        .bind(stored)
        .bind(invoice_id)
        .execute(database.pool())
        .await
        .unwrap();
        let expected = MarketplaceInvoiceStatus::active(
            invoice_id,
            projected,
            None,
            "undetected",
            activated.activated_at(),
            activated.payment_deadline(),
            None,
            None,
            None,
        );
        assert_eq!(
            store.status(&creator(), invoice_id).await.unwrap(),
            Some(expected)
        );
    }

    store
        .resolve(
            &creator(),
            invoice_id,
            paykit_server::persistence::MarketplaceResolutionOutcome::Refunded,
        )
        .await
        .unwrap();
    let resolved_at: OffsetDateTime = sqlx::query_scalar(
        "SELECT resolved_at FROM marketplace_payment_preparations WHERE id = $1",
    )
    .bind(invoice_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(
        store.status(&creator(), invoice_id).await.unwrap(),
        Some(MarketplaceInvoiceStatus::active(
            invoice_id,
            "failed",
            None,
            "undetected",
            activated.activated_at(),
            activated.payment_deadline(),
            None,
            Some("refunded"),
            Some(resolved_at),
        ))
    );

    database.cleanup().await;
}

#[tokio::test]
async fn bitcoin_evidence_keeps_identity_amount_and_first_observation_immutable() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let prepared = prepare(&store).await;
    let invoice_id = prepared.invoice_id();
    let activated = store
        .activate(MarketplaceActivationInput {
            creator: &creator(),
            invoice_id,
            total_sats: 100,
            proposal_acceptance_window: Duration::from_secs(30 * 60),
        })
        .await
        .unwrap()
        .unwrap();
    let first_at = activated.activated_at() + time::Duration::seconds(1);
    let first_outpoint = outpoint(1);
    let targets = store.observation_targets().await.unwrap();

    assert_eq!(
        observe_marketplace_once_at(
            &FixedBatch(vec![ObservedOutput {
                network: BitcoinNetwork::Regtest,
                address: ADDRESS.into(),
                outpoint: first_outpoint,
                sats: 100,
                confirmations: 0,
                present: true,
            }]),
            &store,
            &BitcoinNetwork::Regtest,
            &targets,
            first_at,
        )
        .await,
        Ok(1)
    );
    assert_eq!(
        store.status(&creator(), invoice_id).await.unwrap(),
        Some(MarketplaceInvoiceStatus::active(
            invoice_id,
            "pending",
            None,
            "detected",
            activated.activated_at(),
            activated.payment_deadline(),
            Some(MarketplaceBitcoinStatus::new(
                first_outpoint.txid.to_string(),
                first_outpoint.vout,
                100,
                first_at,
                0,
                true,
                true,
                true,
            )),
            None,
            None,
        ))
    );

    let targets = store.observation_targets().await.unwrap();
    assert_eq!(
        observe_marketplace_once_at(
            &FixedBatch(vec![ObservedOutput {
                network: BitcoinNetwork::Regtest,
                address: ADDRESS.into(),
                outpoint: first_outpoint,
                sats: 100,
                confirmations: 2,
                present: true,
            }]),
            &store,
            &BitcoinNetwork::Regtest,
            &targets,
            first_at + time::Duration::hours(1),
        )
        .await,
        Ok(1)
    );
    let observation: (OffsetDateTime, i32) = sqlx::query_as(
        "SELECT first_observed_at, confirmations FROM bitcoin_observations
         WHERE marketplace_preparation_id = $1 AND active",
    )
    .bind(invoice_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(observation, (first_at, 2));

    let targets = store.observation_targets().await.unwrap();
    assert_eq!(
        observe_marketplace_once_at(
            &FixedBatch(vec![ObservedOutput {
                network: BitcoinNetwork::Regtest,
                address: ADDRESS.into(),
                outpoint: first_outpoint,
                sats: 99,
                confirmations: 3,
                present: true,
            }]),
            &store,
            &BitcoinNetwork::Regtest,
            &targets,
            first_at + time::Duration::hours(2),
        )
        .await,
        Err(ObserverError::Persistence)
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM bitcoin_observations WHERE marketplace_preparation_id = $1",
        )
        .bind(invoice_id)
        .fetch_one(database.pool())
        .await
        .unwrap(),
        1
    );

    let targets = store.observation_targets().await.unwrap();
    observe_marketplace_once_at(
        &FixedBatch(vec![ObservedOutput {
            network: BitcoinNetwork::Regtest,
            address: ADDRESS.into(),
            outpoint: first_outpoint,
            sats: 100,
            confirmations: 0,
            present: false,
        }]),
        &store,
        &BitcoinNetwork::Regtest,
        &targets,
        first_at + time::Duration::hours(3),
    )
    .await
    .unwrap();
    assert_eq!(
        store.status(&creator(), invoice_id).await.unwrap(),
        Some(MarketplaceInvoiceStatus::active(
            invoice_id,
            "pending",
            None,
            "undetected",
            activated.activated_at(),
            activated.payment_deadline(),
            Some(MarketplaceBitcoinStatus::new(
                first_outpoint.txid.to_string(),
                first_outpoint.vout,
                100,
                first_at,
                0,
                false,
                false,
                false,
            )),
            None,
            None,
        ))
    );

    // A late replacement owns its own immutable first-observation evidence. It must
    // not borrow the displaced outpoint's on-time match.
    let replacement_at = activated.payment_deadline() + time::Duration::seconds(1);
    let replacement = outpoint(2);
    let targets = store.observation_targets().await.unwrap();
    observe_marketplace_once_at(
        &FixedBatch(vec![ObservedOutput {
            network: BitcoinNetwork::Regtest,
            address: ADDRESS.into(),
            outpoint: replacement,
            sats: 100,
            confirmations: 1,
            present: true,
        }]),
        &store,
        &BitcoinNetwork::Regtest,
        &targets,
        replacement_at,
    )
    .await
    .unwrap();
    assert_eq!(
        store.status(&creator(), invoice_id).await.unwrap(),
        Some(MarketplaceInvoiceStatus::active(
            invoice_id,
            "pending",
            None,
            "expired",
            activated.activated_at(),
            activated.payment_deadline(),
            Some(MarketplaceBitcoinStatus::new(
                replacement.txid.to_string(),
                replacement.vout,
                100,
                replacement_at,
                1,
                true,
                true,
                false,
            )),
            None,
            None,
        ))
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM bitcoin_observations
             WHERE marketplace_preparation_id = $1",
        )
        .bind(invoice_id)
        .fetch_one(database.pool())
        .await
        .unwrap(),
        2
    );

    let targets = store.observation_targets().await.unwrap();
    observe_marketplace_once_at(
        &FixedBatch(vec![ObservedOutput {
            network: BitcoinNetwork::Regtest,
            address: ADDRESS.into(),
            outpoint: replacement,
            sats: 100,
            confirmations: 6,
            present: true,
        }]),
        &store,
        &BitcoinNetwork::Regtest,
        &targets,
        replacement_at + time::Duration::hours(1),
    )
    .await
    .unwrap();
    for output in [
        ObservedOutput {
            network: BitcoinNetwork::Regtest,
            address: ADDRESS.into(),
            outpoint: replacement,
            sats: 100,
            confirmations: 0,
            present: false,
        },
        ObservedOutput {
            network: BitcoinNetwork::Regtest,
            address: ADDRESS.into(),
            outpoint: outpoint(3),
            sats: 100,
            confirmations: 1,
            present: true,
        },
    ] {
        observe_marketplace_once_at(
            &FixedBatch(vec![output]),
            &store,
            &BitcoinNetwork::Regtest,
            &[ObservationTarget::new(
                ADDRESS,
                Some(paykit_server::bitcoin::TrackedOutput::new(replacement, 100)),
            )],
            replacement_at + time::Duration::hours(2),
        )
        .await
        .unwrap();
    }
    let final_observation: (i32, bool, Vec<u8>) = sqlx::query_as(
        "SELECT confirmations, present, outpoint_lookup_hash
         FROM bitcoin_observations WHERE marketplace_preparation_id = $1 AND active",
    )
    .bind(invoice_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!((final_observation.0, final_observation.1), (6, true));
    assert_eq!(
        final_observation.2,
        crypto()
            .bitcoin_outpoint_lookup_hash(replacement.to_string().as_bytes())
            .as_bytes()
    );

    database.cleanup().await;
}

#[tokio::test]
async fn malformed_active_relations_fail_closed() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let prepared = prepare(&store).await;
    let invoice_id = prepared.invoice_id();
    store
        .activate(MarketplaceActivationInput {
            creator: &creator(),
            invoice_id,
            total_sats: 100,
            proposal_acceptance_window: Duration::from_secs(30 * 60),
        })
        .await
        .unwrap();

    sqlx::query("DELETE FROM outbox WHERE marketplace_preparation_id = $1")
        .bind(invoice_id)
        .execute(database.pool())
        .await
        .unwrap();
    assert_eq!(
        store.status(&creator(), invoice_id).await,
        Err(MarketplaceStatusError::Unavailable)
    );

    database.cleanup().await;
}

#[tokio::test]
async fn lifecycle_states_project_and_exception_states_fail_closed() {
    for state in [
        "proposed",
        "proposal_expired",
        "accepted",
        "rejected",
        "canceled",
        "proof_submitted",
        "active_recurring",
    ] {
        let database = TestDatabase::create().await;
        let store = store(&database).await;
        let invoice_id = prepare(&store).await.invoice_id();
        let activated = store
            .activate(MarketplaceActivationInput {
                creator: &creator(),
                invoice_id,
                total_sats: 100,
                proposal_acceptance_window: Duration::from_secs(30 * 60),
            })
            .await
            .unwrap()
            .unwrap();
        insert_lifecycle(&database, invoice_id, state).await;

        assert_eq!(
            store.status(&creator(), invoice_id).await.unwrap(),
            Some(MarketplaceInvoiceStatus::active(
                invoice_id,
                "pending",
                Some(state),
                "undetected",
                activated.activated_at(),
                activated.payment_deadline(),
                None,
                None,
                None,
            ))
        );
        database.cleanup().await;
    }

    for (state, expected) in [
        (
            "recovery_required",
            MarketplaceStatusError::RecoveryRequired,
        ),
        ("invalid_conflict", MarketplaceStatusError::InvalidConflict),
    ] {
        let database = TestDatabase::create().await;
        let store = store(&database).await;
        let invoice_id = prepare(&store).await.invoice_id();
        store
            .activate(MarketplaceActivationInput {
                creator: &creator(),
                invoice_id,
                total_sats: 100,
                proposal_acceptance_window: Duration::from_secs(30 * 60),
            })
            .await
            .unwrap();
        insert_lifecycle(&database, invoice_id, state).await;
        let service = MarketplaceStatusService::new(Arc::new(store));

        assert_eq!(service.status(&creator(), invoice_id).await, Err(expected));
        database.cleanup().await;
    }
}

#[tokio::test]
async fn inactive_resolution_is_projected_without_payment_fields() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let prepared = prepare(&store).await;
    let invoice_id = prepared.invoice_id();

    let resolution = store
        .resolve(
            &creator(),
            invoice_id,
            paykit_server::persistence::MarketplaceResolutionOutcome::Abandoned,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        store.status(&creator(), invoice_id).await.unwrap(),
        Some(MarketplaceInvoiceStatus::inactive(
            invoice_id,
            "prepared",
            Some("abandoned"),
            Some(resolution.resolved_at()),
        ))
    );

    store.void(&creator(), invoice_id).await.unwrap().unwrap();
    assert_eq!(
        store.status(&creator(), invoice_id).await.unwrap(),
        Some(MarketplaceInvoiceStatus::inactive(
            invoice_id,
            "voided",
            Some("abandoned"),
            Some(resolution.resolved_at()),
        ))
    );

    database.cleanup().await;
}

#[tokio::test]
async fn deadline_expiry_underpayment_and_late_match_are_projected() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let invoice_id = prepare_with_window(&store, 2).await.invoice_id();
    let activated = store
        .activate(MarketplaceActivationInput {
            creator: &creator(),
            invoice_id,
            total_sats: 100,
            proposal_acceptance_window: Duration::from_secs(30 * 60),
        })
        .await
        .unwrap()
        .unwrap();
    let deadline = activated.payment_deadline();

    let targets = store.observation_targets().await.unwrap();
    let underpaid = outpoint(20);
    observe_marketplace_once_at(
        &FixedBatch(vec![ObservedOutput {
            network: BitcoinNetwork::Regtest,
            address: ADDRESS.into(),
            outpoint: underpaid,
            sats: 99,
            confirmations: 1,
            present: true,
        }]),
        &store,
        &BitcoinNetwork::Regtest,
        &targets,
        activated.activated_at() + time::Duration::milliseconds(500),
    )
    .await
    .unwrap();
    assert_eq!(
        store.status(&creator(), invoice_id).await.unwrap(),
        Some(MarketplaceInvoiceStatus::active(
            invoice_id,
            "pending",
            None,
            "confirmed",
            activated.activated_at(),
            deadline,
            Some(MarketplaceBitcoinStatus::new(
                underpaid.txid.to_string(),
                underpaid.vout,
                99,
                activated.activated_at() + time::Duration::milliseconds(500),
                1,
                true,
                false,
                false,
            )),
            None,
            None,
        ))
    );

    tokio::time::sleep(std::time::Duration::from_millis(2_100)).await;
    assert_eq!(
        store.status(&creator(), invoice_id).await.unwrap(),
        Some(MarketplaceInvoiceStatus::active(
            invoice_id,
            "pending",
            None,
            "expired",
            activated.activated_at(),
            deadline,
            Some(MarketplaceBitcoinStatus::new(
                underpaid.txid.to_string(),
                underpaid.vout,
                99,
                activated.activated_at() + time::Duration::milliseconds(500),
                1,
                true,
                false,
                false,
            )),
            None,
            None,
        ))
    );

    let late = outpoint(21);
    let targets = store.observation_targets().await.unwrap();
    observe_marketplace_once_at(
        &FixedBatch(vec![ObservedOutput {
            network: BitcoinNetwork::Regtest,
            address: ADDRESS.into(),
            outpoint: late,
            sats: 100,
            confirmations: 1,
            present: true,
        }]),
        &store,
        &BitcoinNetwork::Regtest,
        &targets,
        deadline + time::Duration::seconds(1),
    )
    .await
    .unwrap();
    assert_eq!(
        store.status(&creator(), invoice_id).await.unwrap(),
        Some(MarketplaceInvoiceStatus::active(
            invoice_id,
            "pending",
            None,
            "expired",
            activated.activated_at(),
            deadline,
            Some(MarketplaceBitcoinStatus::new(
                late.txid.to_string(),
                late.vout,
                100,
                deadline + time::Duration::seconds(1),
                1,
                true,
                true,
                false,
            )),
            None,
            None,
        ))
    );

    database.cleanup().await;
}

#[tokio::test]
async fn observation_waits_for_creator_before_locking_preparation() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let invoice_id = prepare(&store).await.invoice_id();
    let activated = store
        .activate(MarketplaceActivationInput {
            creator: &creator(),
            invoice_id,
            total_sats: 100,
            proposal_acceptance_window: Duration::from_secs(30 * 60),
        })
        .await
        .unwrap()
        .unwrap();
    let creator_id: uuid::Uuid =
        sqlx::query_scalar("SELECT creator_id FROM marketplace_payment_preparations WHERE id = $1")
            .bind(invoice_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    let mut blocker = database.pool().begin().await.unwrap();
    sqlx::query("SELECT id FROM creators WHERE id = $1 FOR UPDATE")
        .bind(creator_id)
        .execute(&mut *blocker)
        .await
        .unwrap();

    let observed_at = activated.activated_at() + time::Duration::seconds(1);
    let store_for_task = store.clone();
    let mut task = tokio::spawn(async move {
        let targets = store_for_task.observation_targets().await.unwrap();
        observe_marketplace_once_at(
            &FixedBatch(vec![ObservedOutput {
                network: BitcoinNetwork::Regtest,
                address: ADDRESS.into(),
                outpoint: outpoint(30),
                sats: 100,
                confirmations: 0,
                present: true,
            }]),
            &store_for_task,
            &BitcoinNetwork::Regtest,
            &targets,
            observed_at,
        )
        .await
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(500), &mut task)
            .await
            .is_err()
    );
    blocker.rollback().await.unwrap();
    assert_eq!(task.await.unwrap(), Ok(1));

    database.cleanup().await;
}

#[tokio::test]
async fn observation_evidence_rejects_direct_rewrite_and_delete() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let prepared = prepare(&store).await;
    let invoice_id = prepared.invoice_id();
    let activated = store
        .activate(MarketplaceActivationInput {
            creator: &creator(),
            invoice_id,
            total_sats: 100,
            proposal_acceptance_window: Duration::from_secs(30 * 60),
        })
        .await
        .unwrap()
        .unwrap();
    let targets = store.observation_targets().await.unwrap();
    observe_marketplace_once_at(
        &FixedBatch(vec![ObservedOutput {
            network: BitcoinNetwork::Regtest,
            address: ADDRESS.into(),
            outpoint: outpoint(9),
            sats: 100,
            confirmations: 0,
            present: true,
        }]),
        &store,
        &BitcoinNetwork::Regtest,
        &targets,
        activated.activated_at() + time::Duration::seconds(1),
    )
    .await
    .unwrap();

    let rewrite = sqlx::query(
        "UPDATE bitcoin_observations SET first_observed_at = first_observed_at + interval '1 second'
         WHERE marketplace_preparation_id = $1",
    )
    .bind(invoice_id)
    .execute(database.pool())
    .await;
    assert!(rewrite.is_err());
    let delete =
        sqlx::query("DELETE FROM bitcoin_observations WHERE marketplace_preparation_id = $1")
            .bind(invoice_id)
            .execute(database.pool())
            .await;
    assert!(delete.is_err());

    sqlx::query(
        "ALTER TABLE bitcoin_observations
         DISABLE TRIGGER bitcoin_observation_evidence_immutable",
    )
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(
        "UPDATE bitcoin_observations SET observation_envelope = decode('00', 'hex')
         WHERE marketplace_preparation_id = $1",
    )
    .bind(invoice_id)
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(
        "ALTER TABLE bitcoin_observations
         ENABLE TRIGGER bitcoin_observation_evidence_immutable",
    )
    .execute(database.pool())
    .await
    .unwrap();
    assert_eq!(
        store.scan_observation_integrity().await,
        Err(PersistenceError::CorruptOrMissing)
    );

    database.cleanup().await;
}
