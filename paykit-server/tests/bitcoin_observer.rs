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
        collections::HashSet,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use async_trait::async_trait;
    use paykit_server::{
        bitcoin::{ObservationTarget, PlannedObservation},
        config::BitcoinNetwork,
        runtime::{DependencyCheck, Runtime},
        workers::observer::{
            AddressFailureGate, ElectrumPort, ObservationBackend, ObservationReport,
            ObserverBackoff, ObserverError, ObserverPolicy, ObserverTickOutcome, TipProbe,
            observe_tick,
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
        }
    }

    fn failure_gate() -> AddressFailureGate {
        AddressFailureGate::new()
    }

    struct FakeElectrum {
        probe: Result<TipProbe, ObserverError>,
        /// Addresses whose per-address lookup fails; every other requested
        /// address is observed successfully.
        failing_addresses: HashSet<String>,
        /// Extra addresses reported as observed even though they were not
        /// requested, modelling an observation stamp whose lookup hash
        /// matches no invoice row.
        ghost_observed: Vec<String>,
        calls: Mutex<Vec<Vec<String>>>,
    }

    impl FakeElectrum {
        fn healthy() -> Self {
            Self {
                probe: Ok(TipProbe {
                    height: 100,
                    time_unix: fresh_tip_time(),
                }),
                failing_addresses: HashSet::new(),
                ghost_observed: Vec::new(),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn failing_addresses<const N: usize>(addresses: [&str; N]) -> Self {
            Self {
                failing_addresses: addresses.into_iter().map(str::to_owned).collect(),
                ..Self::healthy()
            }
        }

        fn with_ghost_observed(mut self, address: &str) -> Self {
            self.ghost_observed.push(address.to_owned());
            self
        }

        fn failing(error: ObserverError) -> Self {
            Self {
                probe: Err(error),
                failing_addresses: HashSet::new(),
                ghost_observed: Vec::new(),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl ElectrumPort for FakeElectrum {
        async fn observations(
            &self,
            _tip_height: u32,
            targets: &[ObservationTarget],
        ) -> Result<ObservationReport, ObserverError> {
            self.calls.lock().unwrap().push(
                targets
                    .iter()
                    .map(|target| target.address().to_owned())
                    .collect(),
            );
            let mut report = ObservationReport::default();
            for target in targets {
                if self.failing_addresses.contains(target.address()) {
                    report.failed.push(target.address().to_owned());
                } else {
                    report.observed.push(target.address().to_owned());
                }
            }
            report.observed.extend(self.ghost_observed.iter().cloned());
            Ok(report)
        }

        async fn probe(&self) -> Result<TipProbe, ObserverError> {
            self.probe
        }
    }

    struct FakeEntry {
        address: String,
        staleness_secs: u64,
    }

    impl FakeEntry {
        fn new(address: &str, staleness_secs: u64) -> Self {
            Self {
                address: address.into(),
                staleness_secs,
            }
        }
    }

    #[derive(Default)]
    struct FakeBackend {
        entries: Mutex<Vec<FakeEntry>>,
        applied: Mutex<Vec<Vec<String>>>,
        stamped: Mutex<Vec<Vec<String>>>,
    }

    #[async_trait]
    impl ObservationBackend for FakeBackend {
        async fn observation_plan(&self) -> Result<Vec<PlannedObservation>, ObserverError> {
            let entries = self.entries.lock().unwrap();
            let mut ordered: Vec<&FakeEntry> = entries.iter().collect();
            // Stable sort on a copy: ties (equally fresh targets) keep the
            // plan's insertion order, mirroring the store's deterministic
            // ORDER BY without reordering the stored entries.
            ordered.sort_by(|left, right| right.staleness_secs.cmp(&left.staleness_secs));
            Ok(ordered
                .into_iter()
                .map(|entry| {
                    PlannedObservation::new(
                        ObservationTarget::new(entry.address.clone(), None),
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
            addresses: &[String],
        ) -> Result<u64, ObserverError> {
            self.stamped.lock().unwrap().push(addresses.to_vec());
            let mut entries = self.entries.lock().unwrap();
            let mut misses = 0_u64;
            for address in addresses {
                match entries.iter_mut().find(|entry| entry.address == *address) {
                    Some(entry) => entry.staleness_secs = 0,
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
            &mut failure_gate(),
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
                &mut failure_gate(),
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
            &mut failure_gate(),
        )
        .await;
        assert_eq!(
            outcome,
            ObserverTickOutcome::Observed {
                processed: 0,
                deferred: 0,
                failed: 0,
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
                FakeEntry::new("oldest", 600),
                FakeEntry::new("second", 300),
                FakeEntry::new("third", 120),
                FakeEntry::new("freshest", 60),
            ]),
            applied: Mutex::new(Vec::new()),
            stamped: Mutex::new(Vec::new()),
        };
        let runtime = runtime();
        // Every target costs exactly one lookup. Policy budget 4 reserves
        // the tick's two probe requests (headers.subscribe +
        // block_header(0)), leaving 2 lookups, which admits the first two
        // targets only. Without the reservation all four would fit and
        // nothing would be deferred.
        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &policy(4),
            &runtime,
            &mut failure_gate(),
        )
        .await;
        assert_eq!(
            outcome,
            ObserverTickOutcome::Observed {
                processed: 2,
                deferred: 2,
                failed: 0,
            }
        );
        assert_eq!(
            port.calls.lock().unwrap().as_slice(),
            &[vec!["oldest".to_owned(), "second".to_owned()]]
        );

        // Next tick: the deferred targets are now the stalest and are
        // observed first; the just-observed pair defers behind them.
        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &policy(4),
            &runtime,
            &mut failure_gate(),
        )
        .await;
        assert_eq!(
            outcome,
            ObserverTickOutcome::Observed {
                processed: 2,
                deferred: 2,
                failed: 0,
            }
        );
        {
            let calls = port.calls.lock().unwrap();
            assert_eq!(calls.len(), 2);
            assert_eq!(calls[1], vec!["third".to_owned(), "freshest".to_owned()]);
        }

        // One more tick observes the rotated remainder: every stamped
        // target reports staleness 0, so the plan's stable order admits the
        // pair deferred behind last tick's head.
        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &policy(4),
            &runtime,
            &mut failure_gate(),
        )
        .await;
        assert_eq!(
            outcome,
            ObserverTickOutcome::Observed {
                processed: 2,
                deferred: 2,
                failed: 0,
            }
        );
        let calls = port.calls.lock().unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[2], vec!["oldest".to_owned(), "second".to_owned()]);
    }

    #[tokio::test]
    async fn the_token_gate_rejects_exactly_one_extra_lookup() {
        // A plan exactly one target larger than the lookup budget: the gate
        // admits the budget exactly and the one extra target is deferred,
        // so the adapter never issues the extra list_unspent call.
        let port = FakeElectrum::healthy();
        let backend = FakeBackend {
            entries: Mutex::new(vec![
                FakeEntry::new("first", 600),
                FakeEntry::new("extra", 300),
            ]),
            applied: Mutex::new(Vec::new()),
            stamped: Mutex::new(Vec::new()),
        };
        let runtime = runtime();
        // Budget 3 minus the two reserved probe requests admits one lookup.
        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &policy(3),
            &runtime,
            &mut failure_gate(),
        )
        .await;
        assert_eq!(
            outcome,
            ObserverTickOutcome::Observed {
                processed: 1,
                deferred: 1,
                failed: 0,
            }
        );
        let calls = port.calls.lock().unwrap();
        assert_eq!(
            calls.as_slice(),
            &[vec!["first".to_owned()]],
            "exactly one lookup is admitted; the extra target is never fetched"
        );
        let entries = backend.entries.lock().unwrap();
        assert_eq!(
            entries[1].staleness_secs, 300,
            "the extra target stays stale"
        );
    }

    #[tokio::test]
    async fn sustained_over_budget_plan_observes_every_target_within_n_ticks() {
        const TARGETS: usize = 5;
        // The lookup budget admits one target per tick, so the plan rotates
        // through every target in TARGETS ticks.
        let port = FakeElectrum::healthy();
        let backend = FakeBackend {
            entries: Mutex::new(
                (0..TARGETS)
                    .map(|index| {
                        FakeEntry::new(&format!("target-{index}"), (1_000 - 100 * index) as u64)
                    })
                    .collect(),
            ),
            applied: Mutex::new(Vec::new()),
            stamped: Mutex::new(Vec::new()),
        };
        let runtime = runtime();

        for _ in 0..TARGETS {
            let outcome = observe_tick(
                &port,
                &backend,
                &BitcoinNetwork::Regtest,
                &policy(3),
                &runtime,
                &mut failure_gate(),
            )
            .await;
            assert_eq!(
                outcome,
                ObserverTickOutcome::Observed {
                    processed: 1,
                    deferred: TARGETS - 1,
                    failed: 0,
                },
                "each tick observes exactly the oldest target"
            );
        }
        let calls = port.calls.lock().unwrap();
        let observed: HashSet<_> = calls.iter().flatten().collect();
        assert_eq!(
            observed.len(),
            TARGETS,
            "every target must be observed within {TARGETS} ticks"
        );
    }

    #[tokio::test]
    async fn a_per_address_failure_isolates_the_failed_target_and_keeps_the_endpoint_available() {
        // One address's lookup fails (for example a dusted address whose
        // response times out): the other targets in the same tick are still
        // applied and stamped, the failed target keeps its staleness and
        // leads the next plan, and Electrum stays available.
        let port = FakeElectrum::failing_addresses(["dusted"]);
        let backend = FakeBackend {
            entries: Mutex::new(vec![
                FakeEntry::new("dusted", 600),
                FakeEntry::new("cheap-a", 300),
                FakeEntry::new("cheap-b", 120),
            ]),
            applied: Mutex::new(Vec::new()),
            stamped: Mutex::new(Vec::new()),
        };
        let runtime = runtime();
        let mut gate = failure_gate();

        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &policy(100),
            &runtime,
            &mut gate,
        )
        .await;
        assert_eq!(
            outcome,
            ObserverTickOutcome::Observed {
                processed: 3,
                deferred: 0,
                failed: 1,
            }
        );
        assert_eq!(
            backend.applied.lock().unwrap().as_slice(),
            &[vec!["cheap-a".to_owned(), "cheap-b".to_owned()]],
            "only successfully observed targets are applied"
        );
        assert_eq!(
            backend.stamped.lock().unwrap().as_slice(),
            &[vec!["cheap-a".to_owned(), "cheap-b".to_owned()]],
            "only successfully observed targets are stamped"
        );
        {
            let entries = backend.entries.lock().unwrap();
            assert_eq!(
                entries[0].staleness_secs, 600,
                "the failed target keeps its staleness"
            );
        }
        let report = runtime.readiness().await;
        assert_eq!(
            report.electrum,
            paykit_server::runtime::ComponentState::Ready,
            "one per-address failure must not degrade the endpoint"
        );

        // Next tick the failed target leads the plan and, succeeding now,
        // is observed and stamped.
        let port = FakeElectrum::healthy();
        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &policy(100),
            &runtime,
            &mut gate,
        )
        .await;
        assert_eq!(
            outcome,
            ObserverTickOutcome::Observed {
                processed: 3,
                deferred: 0,
                failed: 0,
            }
        );
        let calls = port.calls.lock().unwrap();
        assert_eq!(calls[0][0], "dusted".to_owned());
    }

    #[tokio::test]
    async fn repeated_failure_of_one_address_never_degrades_the_endpoint() {
        // The same single address failing on every retry — with no
        // successful lookup anywhere — is an address condition, not an
        // endpoint condition: the gate never trips.
        let port = FakeElectrum::failing_addresses(["dusted"]);
        let backend = FakeBackend {
            entries: Mutex::new(vec![FakeEntry::new("dusted", 600)]),
            applied: Mutex::new(Vec::new()),
            stamped: Mutex::new(Vec::new()),
        };
        let runtime = runtime();
        let mut gate = failure_gate();

        for _ in 0..10 {
            let outcome = observe_tick(
                &port,
                &backend,
                &BitcoinNetwork::Regtest,
                &policy(100),
                &runtime,
                &mut gate,
            )
            .await;
            assert_eq!(
                outcome,
                ObserverTickOutcome::Observed {
                    processed: 1,
                    deferred: 0,
                    failed: 1,
                }
            );
            assert_eq!(
                runtime.readiness().await.electrum,
                paykit_server::runtime::ComponentState::Ready
            );
        }
    }

    #[tokio::test]
    async fn distinct_consecutive_address_failures_degrade_the_endpoint() {
        // Three consecutive per-address failures across distinct addresses
        // with no intervening success are the documented endpoint-level
        // condition: the tick reports Unavailable and the loop backs off.
        let backend = FakeBackend {
            entries: Mutex::new(vec![
                FakeEntry::new("a", 600),
                FakeEntry::new("b", 300),
                FakeEntry::new("c", 120),
            ]),
            applied: Mutex::new(Vec::new()),
            stamped: Mutex::new(Vec::new()),
        };
        let runtime = runtime();
        let mut gate = failure_gate();
        let mut backoff = ObserverBackoff::new();

        // Tick 1: a mixed tick — one success keeps the endpoint healthy and
        // resets the streak even though two lookups failed.
        let port = FakeElectrum::failing_addresses(["a", "b"]);
        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &policy(100),
            &runtime,
            &mut gate,
        )
        .await;
        assert_eq!(
            outcome,
            ObserverTickOutcome::Observed {
                processed: 3,
                deferred: 0,
                failed: 2,
            }
        );
        backoff.record_outcome(&outcome);
        assert!(!backoff.is_backing_off());

        // Tick 2: every admitted lookup fails — three consecutive failures
        // across distinct addresses with no intervening success trip the
        // gate and the endpoint degrades.
        let port = FakeElectrum::failing_addresses(["a", "b", "c"]);
        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &policy(100),
            &runtime,
            &mut gate,
        )
        .await;
        assert_eq!(
            outcome,
            ObserverTickOutcome::ObservationFailed(ObserverError::Unavailable)
        );
        backoff.record_outcome(&outcome);
        assert!(backoff.is_backing_off());
        assert_ne!(
            runtime.readiness().await.electrum,
            paykit_server::runtime::ComponentState::Ready
        );
    }

    #[tokio::test]
    async fn a_stamp_miss_is_reported_without_blocking_the_other_records() {
        // The adapter reports an observed address whose lookup hash matches
        // no invoice row: the miss must surface as a named tick failure
        // while the known target is still stamped.
        let port = FakeElectrum::healthy().with_ghost_observed("ghost");
        let backend = FakeBackend {
            entries: Mutex::new(vec![FakeEntry::new("known", 300)]),
            applied: Mutex::new(Vec::new()),
            stamped: Mutex::new(Vec::new()),
        };
        let runtime = runtime();

        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &policy(100),
            &runtime,
            &mut failure_gate(),
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
    }

    #[tokio::test]
    async fn a_stamp_miss_recovers_availability_and_resets_the_backoff() {
        // Backoff accumulated from an outage must not persist through a
        // stamp miss: the tick reached Electrum and committed the other
        // records, so availability recovers and the backoff resets.
        let port = FakeElectrum::healthy().with_ghost_observed("ghost");
        let backend = FakeBackend {
            entries: Mutex::new(vec![FakeEntry::new("known", 300)]),
            applied: Mutex::new(Vec::new()),
            stamped: Mutex::new(Vec::new()),
        };
        let runtime = runtime();
        let mut backoff = ObserverBackoff::new();
        backoff.record_failure();
        backoff.record_failure();
        assert_eq!(backoff.delay(), Duration::from_secs(60));

        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &policy(100),
            &runtime,
            &mut failure_gate(),
        )
        .await;
        assert_eq!(
            outcome,
            ObserverTickOutcome::ObservationFailed(ObserverError::ObservationStampMiss)
        );
        backoff.record_outcome(&outcome);
        assert!(!backoff.is_backing_off());
        assert_eq!(backoff.delay(), Duration::ZERO);
        let report = runtime.readiness().await;
        assert_eq!(
            report.electrum,
            paykit_server::runtime::ComponentState::Ready,
            "a stamp miss must not leave Electrum degraded after recovery"
        );
    }

    #[tokio::test]
    async fn the_backlog_gauge_tracks_the_oldest_pending_target() {
        let port = FakeElectrum::healthy();
        let backend = FakeBackend {
            entries: Mutex::new(vec![
                FakeEntry::new("stale", 600),
                FakeEntry::new("fresh", 120),
            ]),
            applied: Mutex::new(Vec::new()),
            stamped: Mutex::new(Vec::new()),
        };
        let runtime = runtime();

        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &policy(100),
            &runtime,
            &mut failure_gate(),
        )
        .await;
        assert!(matches!(outcome, ObserverTickOutcome::Observed { .. }));
        let encoded = runtime.metrics().encode().unwrap();
        assert!(
            encoded.contains("paykit_electrum_backlog_oldest_age_seconds 600"),
            "the gauge must track the oldest pending target: {encoded}"
        );
    }

    #[tokio::test]
    async fn per_address_failures_are_counted_for_operators() {
        let port = FakeElectrum::failing_addresses(["dusted"]);
        let backend = FakeBackend {
            entries: Mutex::new(vec![
                FakeEntry::new("dusted", 600),
                FakeEntry::new("cheap", 300),
            ]),
            applied: Mutex::new(Vec::new()),
            stamped: Mutex::new(Vec::new()),
        };
        let runtime = runtime();

        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &policy(100),
            &runtime,
            &mut failure_gate(),
        )
        .await;
        assert!(matches!(outcome, ObserverTickOutcome::Observed { .. }));
        let encoded = runtime.metrics().encode().unwrap();
        assert!(
            encoded.contains("paykit_electrum_observation_address_failures_total 1"),
            "the isolated failure must be counted: {encoded}"
        );
    }
}
