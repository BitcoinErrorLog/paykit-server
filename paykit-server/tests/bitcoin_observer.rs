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

    fn policy(budget: u32) -> ObserverPolicy {
        ObserverPolicy {
            poll_interval: Duration::from_secs(10),
            max_requests_per_tick: budget,
            max_requests_per_second: 100,
        }
    }

    struct FakeElectrum {
        probe: Result<TipProbe, ObserverError>,
        calls: Mutex<Vec<Vec<String>>>,
    }

    impl FakeElectrum {
        fn healthy() -> Self {
            Self {
                probe: Ok(TipProbe {
                    height: 100,
                    time_unix: 1_700_000_000,
                }),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn failing(error: ObserverError) -> Self {
            Self {
                probe: Err(error),
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
            Ok(ObservationReport {
                outputs: Vec::new(),
                history: targets
                    .iter()
                    .map(|target| TargetHistory {
                        address: target.address().to_owned(),
                        tx_count: 0,
                    })
                    .collect(),
            })
        }

        async fn probe(&self) -> Result<TipProbe, ObserverError> {
            self.probe
        }
    }

    struct FakeEntry {
        address: String,
        history_tx_count: Option<u32>,
        staleness_secs: u64,
    }

    #[derive(Default)]
    struct FakeBackend {
        entries: Mutex<Vec<FakeEntry>>,
        applied: Mutex<Vec<Vec<String>>>,
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
                        Duration::from_secs(entry.staleness_secs),
                    )
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

        async fn record_observation_tick(
            &self,
            records: &[TargetTickRecord],
        ) -> Result<(), ObserverError> {
            let mut entries = self.entries.lock().unwrap();
            for record in records {
                let entry = entries
                    .iter_mut()
                    .find(|entry| entry.address == record.address())
                    .expect("recorded target is in the plan");
                entry.staleness_secs = 0;
                entry.history_tx_count = Some(record.history_tx_count());
            }
            Ok(())
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
                FakeEntry {
                    address: "oldest".into(),
                    history_tx_count: None,
                    staleness_secs: 600,
                },
                FakeEntry {
                    address: "second".into(),
                    history_tx_count: Some(2),
                    staleness_secs: 300,
                },
                FakeEntry {
                    address: "third".into(),
                    history_tx_count: Some(0),
                    staleness_secs: 120,
                },
                FakeEntry {
                    address: "freshest".into(),
                    history_tx_count: Some(0),
                    staleness_secs: 60,
                },
            ]),
            applied: Mutex::new(Vec::new()),
        };
        let runtime = runtime();
        // Costs: 2 + 3 + 1 + 1 = 7 estimated; budget 5 admits the first two.
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
            &policy(5),
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
}
