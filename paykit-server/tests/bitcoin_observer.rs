use bitcoin::{OutPoint, Txid, hashes::Hash};
use paykit_server::{
    bitcoin::{DirectBinding, ObservationAction, ObservationTarget, ObservedOutput, TrackedOutput},
    config::BitcoinNetwork,
};

fn outpoint(label: u8) -> OutPoint {
    OutPoint::new(Txid::from_byte_array([label; 32]), 0)
}

fn binding(label: u8, sats: u64, confirmations: u32, present: bool) -> DirectBinding {
    DirectBinding::new(outpoint(label).to_string(), sats, confirmations, present)
}

fn output(label: u8, sats: u64, confirmations: u32, present: bool) -> ObservedOutput {
    ObservedOutput {
        network: BitcoinNetwork::Regtest,
        address: "bcrt1invoice".into(),
        outpoint: outpoint(label),
        sats,
        confirmations,
        present,
    }
}

#[test]
fn direct_output_status_is_factual_and_confirmation_based() {
    let mut observed = output(1, 101, 0, true);
    assert_eq!(observed.status(), "detected");
    observed.confirmations = 1;
    assert_eq!(observed.status(), "confirmed");
    observed.present = false;
    assert_eq!(observed.status(), "undetected");
}

#[test]
fn amount_matched_zero_conf_output_can_be_replaced() {
    let current = binding(1, 100, 0, true);
    assert_eq!(
        current.action_for(&output(2, 100, 0, true), 100),
        ObservationAction::Replace
    );
}

#[test]
fn one_confirmation_freezes_amount_matched_output_until_reorg() {
    let confirmed = binding(1, 100, 1, true);
    assert_eq!(
        confirmed.action_for(&output(2, 100, 0, true), 100),
        ObservationAction::Ignore
    );
    let reorged = binding(1, 100, 0, true);
    assert_eq!(
        reorged.action_for(&output(2, 100, 0, true), 100),
        ObservationAction::Replace
    );
}

#[test]
fn underpayment_remains_replaceable_at_every_confirmation_count() {
    let underpaid = binding(1, 99, 42, true);
    assert_eq!(
        underpaid.action_for(&output(2, 100, 0, true), 100),
        ObservationAction::Replace
    );
}

#[test]
fn matching_six_confirmation_output_is_final_at_exactly_six() {
    let final_output = binding(1, 100, 9, true);
    assert!(final_output.is_final(100));
    assert_eq!(final_output.reported_confirmations(100), 6);
    assert_eq!(
        final_output.action_for(&output(2, 100, 0, true), 100),
        ObservationAction::Ignore
    );
}

#[test]
fn bitcoin_observation_debug_redacts_addresses_and_outpoints() {
    let outpoint = outpoint(9);
    let address = "bcrt1qinvoiceaddress";
    let target = ObservationTarget::new(address, Some(TrackedOutput::new(outpoint, 100)));
    let observed = ObservedOutput {
        network: BitcoinNetwork::Regtest,
        address: address.into(),
        outpoint,
        sats: 100,
        confirmations: 0,
        present: true,
    };
    let binding = DirectBinding::new(outpoint.to_string(), 100, 0, true);

    for debug in [
        format!("{target:?}"),
        format!("{:?}", target.current().unwrap()),
        format!("{observed:?}"),
        format!("{binding:?}"),
    ] {
        assert!(!debug.contains(address));
        assert!(!debug.contains(&outpoint.to_string()));
    }
}

mod tick {
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };

    use async_trait::async_trait;
    use paykit_server::{
        bitcoin::{ObservationTarget, PlannedObservation, TargetTickRecord},
        config::BitcoinNetwork,
        runtime::{DependencyCheck, Runtime},
        workers::observer::{
            ElectrumPort, ObservationBackend, ObservationReport, ObserverBackoff, ObserverError,
            ObserverPolicy, ObserverTickOutcome, TargetHistory, TipProbe, observe_tick,
        },
    };

    struct ReadyPostgres;

    #[async_trait]
    impl DependencyCheck for ReadyPostgres {
        async fn postgres_ready(&self) -> bool {
            true
        }
    }

    fn runtime() -> Runtime {
        Runtime::new(Arc::new(ReadyPostgres), 1)
    }

    fn fresh_tip_time() -> u32 {
        u32::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap()
    }

    fn policy(budget: u32) -> ObserverPolicy {
        ObserverPolicy {
            poll_interval: Duration::from_secs(10),
            max_requests_per_tick: budget,
            max_requests_per_second: 100,
            max_target_requests: 500,
        }
    }

    struct FakeElectrum {
        probe: Result<TipProbe, ObserverError>,
        history_tx_counts: std::collections::HashMap<String, u32>,
        request_count: u64,
        extra_history: Vec<TargetHistory>,
        calls: Mutex<Vec<Vec<String>>>,
    }

    impl FakeElectrum {
        fn healthy() -> Self {
            Self::healthy_with_history([])
        }

        fn healthy_with_history<const N: usize>(history_tx_counts: [(&str, u32); N]) -> Self {
            Self {
                probe: Ok(TipProbe {
                    height: 100,
                    time_unix: fresh_tip_time(),
                }),
                history_tx_counts: history_tx_counts
                    .into_iter()
                    .map(|(address, tx_count)| (address.to_owned(), tx_count))
                    .collect(),
                request_count: 0,
                extra_history: Vec::new(),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn with_request_count(mut self, request_count: u64) -> Self {
            self.request_count = request_count;
            self
        }

        /// Appends a history entry for an address that is not part of the
        /// requested batch, modelling an observation stamp whose lookup
        /// hash matches no invoice row.
        fn with_ghost_history(mut self, address: &str) -> Self {
            self.extra_history.push(TargetHistory {
                address: address.into(),
                tx_count: 0,
            });
            self
        }

        fn failing(error: ObserverError) -> Self {
            Self {
                probe: Err(error),
                history_tx_counts: std::collections::HashMap::new(),
                request_count: 0,
                extra_history: Vec::new(),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl ElectrumPort for FakeElectrum {
        async fn observations(
            &self,
            targets: &[ObservationTarget],
        ) -> Result<ObservationReport, ObserverError> {
            self.calls.lock().unwrap().push(
                targets
                    .iter()
                    .map(|target| target.address().to_owned())
                    .collect(),
            );
            let mut history: Vec<TargetHistory> = targets
                .iter()
                .map(|target| TargetHistory {
                    address: target.address().to_owned(),
                    tx_count: self
                        .history_tx_counts
                        .get(target.address())
                        .copied()
                        .unwrap_or(0),
                })
                .collect();
            history.extend(self.extra_history.iter().cloned());
            Ok(ObservationReport {
                outputs: Vec::new(),
                history,
                request_count: self.request_count,
            })
        }

        async fn probe(&self) -> Result<TipProbe, ObserverError> {
            self.probe
        }
    }

    struct FakeEntry {
        address: String,
        history_tx_count: Option<u32>,
        last_request_count: Option<u32>,
        staleness_secs: u64,
        observation_overrun: bool,
    }

    impl FakeEntry {
        fn new(address: &str, history_tx_count: Option<u32>, staleness_secs: u64) -> Self {
            Self {
                address: address.into(),
                history_tx_count,
                last_request_count: None,
                staleness_secs,
                observation_overrun: false,
            }
        }
    }

    #[derive(Default)]
    struct FakeBackend {
        entries: Mutex<Vec<FakeEntry>>,
        applied: Mutex<Vec<Vec<String>>>,
        marked_overrun: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl ObservationBackend for FakeBackend {
        async fn observation_plan(&self) -> Result<Vec<PlannedObservation>, ObserverError> {
            let mut entries = self.entries.lock().unwrap();
            entries.sort_by(|left, right| right.staleness_secs.cmp(&left.staleness_secs));
            Ok(entries
                .iter()
                .map(|entry| {
                    PlannedObservation::new(
                        ObservationTarget::new(entry.address.clone(), None),
                        entry.history_tx_count,
                        entry.last_request_count,
                        Duration::from_secs(entry.staleness_secs),
                    )
                    .with_observation_overrun(entry.observation_overrun)
                })
                .collect())
        }

        async fn apply_observations(
            &self,
            _network: &BitcoinNetwork,
            targets: &[ObservationTarget],
            _outputs: Vec<paykit_server::bitcoin::ObservedOutput>,
        ) -> Result<usize, ObserverError> {
            self.applied.lock().unwrap().push(
                targets
                    .iter()
                    .map(|target| target.address().to_owned())
                    .collect(),
            );
            Ok(0)
        }

        async fn mark_observation_overrun(
            &self,
            addresses: &[String],
        ) -> Result<Vec<uuid::Uuid>, ObserverError> {
            let mut marked = self.marked_overrun.lock().unwrap();
            let mut entries = self.entries.lock().unwrap();
            let mut invoice_ids = Vec::new();
            for address in addresses {
                marked.push(address.clone());
                if let Some(entry) = entries.iter_mut().find(|entry| entry.address == *address)
                    && !entry.observation_overrun
                {
                    entry.observation_overrun = true;
                    invoice_ids.push(uuid::Uuid::new_v4());
                }
            }
            Ok(invoice_ids)
        }

        async fn record_observation_tick(
            &self,
            records: &[TargetTickRecord],
        ) -> Result<u64, ObserverError> {
            let mut entries = self.entries.lock().unwrap();
            let mut misses = 0_u64;
            for record in records {
                match entries
                    .iter_mut()
                    .find(|entry| entry.address == record.address())
                {
                    Some(entry) => {
                        entry.staleness_secs = 0;
                        entry.history_tx_count = Some(record.history_tx_count());
                        entry.last_request_count = Some(record.request_count());
                    }
                    None => misses += 1,
                }
            }
            Ok(misses)
        }
    }

    #[tokio::test]
    async fn wrong_genesis_probe_marks_health_unavailable_with_a_named_error() {
        let port = FakeElectrum::failing(ObserverError::WrongNetwork);
        let backend = FakeBackend::default();
        let runtime = runtime();

        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &policy(100),
            &runtime,
        )
        .await;

        assert_eq!(
            outcome,
            ObserverTickOutcome::ProbeFailed(ObserverError::WrongNetwork)
        );
        let report = runtime.readiness().await;
        assert_ne!(
            report.electrum,
            paykit_server::runtime::ComponentState::Ready
        );
        assert!(!report.electrum_probe.available);
        assert!(!report.electrum_probe.genesis_ok);
        assert!(report.electrum_probe.last_probe_at.is_some());
        assert!(port.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn unavailable_probe_drives_the_documented_backoff_progression() {
        let port = FakeElectrum::failing(ObserverError::Unavailable);
        let backend = FakeBackend::default();
        let runtime = runtime();
        let mut backoff = ObserverBackoff::new();

        for expected_delay in [30, 60, 120, 240, 480, 900, 900] {
            let outcome = observe_tick(
                &port,
                &backend,
                &BitcoinNetwork::Regtest,
                &policy(100),
                &runtime,
            )
            .await;
            assert_eq!(
                outcome,
                ObserverTickOutcome::ProbeFailed(ObserverError::Unavailable)
            );
            backoff.record_failure();
            assert_eq!(backoff.delay(), Duration::from_secs(expected_delay));
        }

        // A subsequent healthy probe resets the schedule.
        let port = FakeElectrum::healthy();
        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &policy(100),
            &runtime,
        )
        .await;
        assert_eq!(
            outcome,
            ObserverTickOutcome::Observed {
                processed: 0,
                deferred: 0
            }
        );
        backoff.reset();
        assert_eq!(backoff.delay(), Duration::ZERO);
        let report = runtime.readiness().await;
        assert!(report.electrum_probe.available);
        assert_eq!(report.electrum_probe.tip_height, Some(100));
    }

    #[tokio::test]
    async fn budget_exhaustion_defers_the_remainder_to_the_next_tick() {
        let port = FakeElectrum::healthy();
        let backend = FakeBackend {
            entries: Mutex::new(vec![
                FakeEntry::new("oldest", None, 600),
                FakeEntry::new("second", Some(2), 300),
                FakeEntry::new("third", Some(0), 120),
                FakeEntry::new("freshest", Some(0), 60),
            ]),
            applied: Mutex::new(Vec::new()),
            marked_overrun: Mutex::new(Vec::new()),
        };
        let runtime = runtime();
        // Costs: 2 + 3 + 1 + 1 = 7 estimated. Policy budget 7 reserves the
        // tick's two probe requests (headers.subscribe + block_header(0)),
        // leaving 5, which admits the first two targets only. Without the
        // reservation all four would fit and nothing would be deferred.
        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &policy(7),
            &runtime,
        )
        .await;
        assert_eq!(
            outcome,
            ObserverTickOutcome::Observed {
                processed: 2,
                deferred: 2
            }
        );
        assert_eq!(
            port.calls.lock().unwrap().as_slice(),
            &[vec!["oldest".to_owned(), "second".to_owned()]]
        );

        // Next tick: the deferred targets are now the stalest and are observed
        // first; the just-observed pair fits the remaining budget behind them.
        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &policy(7),
            &runtime,
        )
        .await;
        assert_eq!(
            outcome,
            ObserverTickOutcome::Observed {
                processed: 4,
                deferred: 0
            }
        );
        let calls = port.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1][..2], ["third".to_owned(), "freshest".to_owned()]);
    }

    #[tokio::test]
    async fn sustained_over_budget_plan_observes_every_target_within_n_ticks() {
        const TARGETS: usize = 5;
        // Every target alone costs more than the whole per-tick budget
        // (1 history fetch + 9 known transactions = 10 > 5), so only the
        // head-of-line bypass can admit one target per tick.
        let port = FakeElectrum::healthy_with_history([
            ("target-0", 9),
            ("target-1", 9),
            ("target-2", 9),
            ("target-3", 9),
            ("target-4", 9),
        ]);
        let backend = FakeBackend {
            entries: Mutex::new(
                (0..TARGETS)
                    .map(|index| {
                        FakeEntry::new(
                            &format!("target-{index}"),
                            Some(9),
                            (1_000 - 100 * index) as u64,
                        )
                    })
                    .collect(),
            ),
            applied: Mutex::new(Vec::new()),
            marked_overrun: Mutex::new(Vec::new()),
        };
        let runtime = runtime();

        for _ in 0..TARGETS {
            let outcome = observe_tick(
                &port,
                &backend,
                &BitcoinNetwork::Regtest,
                &policy(5),
                &runtime,
            )
            .await;
            assert_eq!(
                outcome,
                ObserverTickOutcome::Observed {
                    processed: 1,
                    deferred: TARGETS - 1
                },
                "each tick observes exactly the oldest target"
            );
        }
        let calls = port.calls.lock().unwrap();
        let observed: std::collections::HashSet<_> = calls.iter().flatten().collect();
        assert_eq!(
            observed.len(),
            TARGETS,
            "every target must be observed within {TARGETS} ticks"
        );
    }

    #[tokio::test]
    async fn one_dusted_target_never_starves_cheap_targets_and_is_itself_observed() {
        // An attacker dusts one published invoice address with ten times the
        // per-tick budget in cheap transactions (cost 1 + 50 = 51 > 5).
        let port = FakeElectrum::healthy_with_history([("dusted", 50)]);
        let backend = FakeBackend {
            entries: Mutex::new(vec![
                FakeEntry::new("dusted", Some(50), 600),
                FakeEntry::new("cheap-a", Some(0), 300),
                FakeEntry::new("cheap-b", Some(0), 120),
            ]),
            applied: Mutex::new(Vec::new()),
            marked_overrun: Mutex::new(Vec::new()),
        };
        let runtime = runtime();

        const TICKS: usize = 6;
        for _ in 0..TICKS {
            let outcome = observe_tick(
                &port,
                &backend,
                &BitcoinNetwork::Regtest,
                &policy(5),
                &runtime,
            )
            .await;
            assert!(matches!(outcome, ObserverTickOutcome::Observed { .. }));
            let calls = port.calls.lock().unwrap();
            let batch = calls.last().expect("a tick observes a batch");
            for cheap in ["cheap-a", "cheap-b"] {
                assert!(
                    batch.contains(&cheap.to_owned()),
                    "cheap targets must be observed every tick"
                );
            }
        }
        let calls = port.calls.lock().unwrap();
        let dusted_ticks = calls
            .iter()
            .filter(|batch| batch.contains(&"dusted".to_owned()))
            .count();
        assert!(
            dusted_ticks >= TICKS / 3,
            "the dusted target must be observed at least once per three ticks, got {dusted_ticks} of {TICKS}"
        );
    }

    #[tokio::test]
    async fn measured_batch_cost_is_attributed_to_the_dusted_target_not_the_batch() {
        const CHEAP: usize = 20;
        // One target dusted to 200 history transactions batched with twenty
        // cheap targets; the measured batch cost (242 requests) must be
        // attributed to the targets' own structural estimates, not split
        // evenly (even split would stamp every cheap target with
        // ceil(242/21) = 12 and collapse the next tick's throughput).
        let port = FakeElectrum::healthy_with_history([("dusted", 200)]).with_request_count(242);
        let mut entries = vec![FakeEntry::new("dusted", Some(200), 600)];
        entries.extend(
            (0..CHEAP).map(|index| FakeEntry::new(&format!("cheap-{index}"), Some(0), 300)),
        );
        let backend = FakeBackend {
            entries: Mutex::new(entries),
            applied: Mutex::new(Vec::new()),
            marked_overrun: Mutex::new(Vec::new()),
        };
        let runtime = runtime();

        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &policy(100),
            &runtime,
        )
        .await;
        assert!(
            matches!(outcome, ObserverTickOutcome::Observed { .. }),
            "the mixed batch must be observed: {outcome:?}"
        );
        {
            let entries = backend.entries.lock().unwrap();
            let dusted = entries
                .iter()
                .find(|entry| entry.address == "dusted")
                .expect("dusted target recorded");
            assert!(
                dusted.last_request_count.unwrap_or(0) >= 200,
                "the dusted target must absorb its own measured cost, got {:?}",
                dusted.last_request_count
            );
            for entry in entries.iter().filter(|entry| entry.address != "dusted") {
                assert!(
                    entry.last_request_count.unwrap_or(u32::MAX) <= 2,
                    "cheap target {} must keep a small persisted request count, got {:?}",
                    entry.address,
                    entry.last_request_count
                );
            }
        }

        // Next tick: every cheap target's persisted request count is small,
        // so the whole cheap set fits the budget behind the bypassed dusted
        // head and is admitted.
        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &policy(100),
            &runtime,
        )
        .await;
        assert!(
            matches!(outcome, ObserverTickOutcome::Observed { .. }),
            "the next tick must observe: {outcome:?}"
        );
        let calls = port.calls.lock().unwrap();
        let batch = calls.last().expect("a tick observes a batch");
        for index in 0..CHEAP {
            assert!(
                batch.contains(&format!("cheap-{index}")),
                "cheap target {index} must be admitted on the next tick"
            );
        }
    }

    #[tokio::test]
    async fn a_head_beyond_the_target_bound_is_flagged_and_loses_the_bypass() {
        // The head's estimate (1 + 600 history transactions) exceeds
        // max_target_requests (500): it is still observed this tick for
        // liveness, but flagged observation_overrun so it can no longer
        // monopolise the endpoint from the next tick on.
        let port = FakeElectrum::healthy_with_history([("huge", 600)]);
        let backend = FakeBackend {
            entries: Mutex::new(vec![
                FakeEntry::new("huge", Some(600), 600),
                FakeEntry::new("cheap", Some(0), 300),
            ]),
            applied: Mutex::new(Vec::new()),
            marked_overrun: Mutex::new(Vec::new()),
        };
        let runtime = runtime();

        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &policy(100),
            &runtime,
        )
        .await;
        assert_eq!(
            outcome,
            ObserverTickOutcome::Observed {
                processed: 2,
                deferred: 0
            },
            "the over-bound head is still observed once, for liveness"
        );
        assert_eq!(
            backend.marked_overrun.lock().unwrap().as_slice(),
            &["huge".to_owned()],
            "the over-bound head must be flagged observation_overrun"
        );
        {
            let entries = backend.entries.lock().unwrap();
            let huge = entries
                .iter()
                .find(|entry| entry.address == "huge")
                .expect("huge target recorded");
            assert!(huge.observation_overrun);
        }

        // Next tick: the flagged head no longer bypasses the budget, so it
        // is deferred and only the cheap target is observed; the overrun
        // count is published for the health surface and metrics.
        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &policy(100),
            &runtime,
        )
        .await;
        assert_eq!(
            outcome,
            ObserverTickOutcome::Observed {
                processed: 1,
                deferred: 1
            },
            "the flagged head is deferred instead of bypassing again"
        );
        {
            let calls = port.calls.lock().unwrap();
            assert_eq!(calls.len(), 2);
            assert_eq!(calls[1], vec!["cheap".to_owned()]);
        }
        assert_eq!(runtime.readiness().await.electrum_overrun_targets, 1);
    }

    #[tokio::test]
    async fn a_stamp_miss_is_reported_without_blocking_the_other_records() {
        // The adapter reports history for an address whose lookup hash
        // matches no invoice row: the miss must surface as a named tick
        // failure while the known target is still stamped.
        let port = FakeElectrum::healthy().with_ghost_history("ghost");
        let backend = FakeBackend {
            entries: Mutex::new(vec![FakeEntry::new("known", Some(0), 300)]),
            applied: Mutex::new(Vec::new()),
            marked_overrun: Mutex::new(Vec::new()),
        };
        let runtime = runtime();

        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &policy(100),
            &runtime,
        )
        .await;
        assert_eq!(
            outcome,
            ObserverTickOutcome::ObservationFailed(ObserverError::ObservationStampMiss),
            "an unmatched stamp must fail the tick with the named error"
        );
        let entries = backend.entries.lock().unwrap();
        assert_eq!(
            entries[0].staleness_secs, 0,
            "the known record must still be stamped"
        );
        assert_eq!(entries[0].history_tx_count, Some(0));
    }
}
