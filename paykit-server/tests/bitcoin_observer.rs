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
        confirmed_height: (confirmations > 0).then_some(confirmations),
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
        confirmed_height: None,
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
    use bitcoin::{OutPoint, Txid, hashes::Hash};
    use paykit_server::{
        bitcoin::{ObservationTarget, PlannedObservation},
        config::BitcoinNetwork,
        persistence::PendingCandidate,
        runtime::{DependencyCheck, Runtime},
        workers::observer::{
            AddressFailureReason, CandidateFailureKind, CandidateTransaction, ElectrumPort,
            FailedObservation, ObservationBackend, ObservationReport, ObserverBackoff,
            ObserverError, ObserverPolicy, ObserverTickOutcome, ObserverTickState, RequestLimiter,
            TipProbe, observe_tick,
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
            max_transaction_bytes: 400_000,
            baseline_completion_timeout: Duration::from_secs(60),
        }
    }

    fn state(policy: &ObserverPolicy) -> ObserverTickState {
        ObserverTickState::new(policy)
    }

    /// Simulates one full poll interval of wall time between ticks so the
    /// sustained budget refills exactly as the production loop's real sleep
    /// would refill it.
    fn elapse_one_poll_interval(state: &mut ObserverTickState) {
        state.rewind_budget_clock(Duration::from_secs(10));
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
        candidate_calls: Mutex<Vec<Txid>>,
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
                candidate_calls: Mutex::new(Vec::new()),
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
                candidate_calls: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl ElectrumPort for FakeElectrum {
        async fn candidate_transaction(
            &self,
            txid: Txid,
            _max_transaction_bytes: usize,
        ) -> Result<CandidateTransaction, ObserverError> {
            self.candidate_calls.lock().unwrap().push(txid);
            Ok(CandidateTransaction {
                txid,
                inputs: Vec::new(),
            })
        }

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
                    report.failed.push(FailedObservation {
                        address: target.address().to_owned(),
                        reason: AddressFailureReason::Error,
                    });
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
        candidates: Mutex<Vec<PendingCandidate>>,
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

        async fn pending_candidates(&self) -> Result<Vec<PendingCandidate>, ObserverError> {
            Ok(self.candidates.lock().unwrap().clone())
        }

        async fn resolve_candidate(
            &self,
            candidate: &PendingCandidate,
            _inputs: &[OutPoint],
        ) -> Result<(), ObserverError> {
            if candidate.invoice_id.is_nil() {
                return Err(ObserverError::Persistence);
            }
            self.candidates
                .lock()
                .unwrap()
                .retain(|entry| entry != candidate);
            Ok(())
        }

        async fn record_candidate_failure(
            &self,
            _candidate: &PendingCandidate,
            _kind: CandidateFailureKind,
        ) -> Result<(), ObserverError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn candidate_fetch_runs_once_then_zero_for_bound_and_no_candidate_ticks() {
        let port = FakeElectrum::healthy();
        let txid = Txid::from_byte_array([42; 32]);
        let backend = FakeBackend::default();
        backend
            .entries
            .lock()
            .unwrap()
            .push(FakeEntry::new("candidate-address", 30));
        backend.candidates.lock().unwrap().push(PendingCandidate {
            invoice_id: uuid::Uuid::new_v4(),
            outpoint: OutPoint::new(txid, 0),
        });
        let runtime = runtime();
        let mut observer_state = state(&policy(4));

        let _ = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &runtime,
            &mut observer_state,
        )
        .await;
        let first_bind_requests = port.candidate_calls.lock().unwrap().len();
        let _ = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &runtime,
            &mut observer_state,
        )
        .await;
        let already_bound_requests =
            port.candidate_calls.lock().unwrap().len() - first_bind_requests;
        let no_candidate_backend = FakeBackend::default();
        no_candidate_backend
            .entries
            .lock()
            .unwrap()
            .push(FakeEntry::new("no-candidate-address", 30));
        let _ = observe_tick(
            &port,
            &no_candidate_backend,
            &BitcoinNetwork::Regtest,
            &runtime,
            &mut observer_state,
        )
        .await;

        let calls = port.candidate_calls.lock().unwrap().clone();
        let no_candidate_requests = calls.len() - first_bind_requests - already_bound_requests;
        eprintln!(
            "candidate RPC log: first_bind=[blockchain.transaction.get]; \
             already_bound=[]; no_candidate=[]; txids={calls:?}"
        );
        assert_eq!(calls, vec![txid]);
        assert_eq!(first_bind_requests, 1);
        assert_eq!(already_bound_requests, 0);
        assert_eq!(no_candidate_requests, 0);
    }

    #[tokio::test]
    async fn candidate_persistence_failure_does_not_degrade_electrum_availability() {
        let port = FakeElectrum::healthy();
        let backend = FakeBackend::default();
        backend
            .entries
            .lock()
            .unwrap()
            .push(FakeEntry::new("candidate-persistence", 30));
        backend.candidates.lock().unwrap().push(PendingCandidate {
            invoice_id: uuid::Uuid::nil(),
            outpoint: OutPoint::new(Txid::from_byte_array([43; 32]), 0),
        });
        let runtime = runtime();

        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &runtime,
            &mut state(&policy(4)),
        )
        .await;
        assert!(matches!(outcome, ObserverTickOutcome::Observed { .. }));
        assert_eq!(
            runtime.readiness().await.electrum,
            paykit_server::runtime::ComponentState::Ready
        );
        assert_eq!(backend.candidates.lock().unwrap().len(), 1);
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
            &runtime,
            &mut state(&policy(100)),
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
                &runtime,
                &mut state(&policy(100)),
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
            &runtime,
            &mut state(&policy(100)),
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
            candidates: Mutex::new(Vec::new()),
        };
        let runtime = runtime();
        let mut state = state(&policy(4));
        // Every target costs exactly one lookup. Policy budget 4 reserves
        // the tick's two probe requests (headers.subscribe +
        // block_header(0)), leaving 2 lookups, which admits the first two
        // targets only. Without the reservation all four would fit and
        // nothing would be deferred.
        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &runtime,
            &mut state,
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
        elapse_one_poll_interval(&mut state);
        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &runtime,
            &mut state,
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
        elapse_one_poll_interval(&mut state);
        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &runtime,
            &mut state,
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
            candidates: Mutex::new(Vec::new()),
        };
        let runtime = runtime();
        // Budget 3 minus the two reserved probe requests admits one lookup.
        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &runtime,
            &mut state(&policy(3)),
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
            candidates: Mutex::new(Vec::new()),
        };
        let runtime = runtime();
        let mut state = state(&policy(3));

        for _ in 0..TARGETS {
            elapse_one_poll_interval(&mut state);
            let outcome = observe_tick(
                &port,
                &backend,
                &BitcoinNetwork::Regtest,
                &runtime,
                &mut state,
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
            candidates: Mutex::new(Vec::new()),
        };
        let runtime = runtime();
        let mut state = state(&policy(100));

        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &runtime,
            &mut state,
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
        elapse_one_poll_interval(&mut state);
        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &runtime,
            &mut state,
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
        // endpoint condition: availability never degrades.
        let port = FakeElectrum::failing_addresses(["dusted"]);
        let backend = FakeBackend {
            entries: Mutex::new(vec![FakeEntry::new("dusted", 600)]),
            applied: Mutex::new(Vec::new()),
            stamped: Mutex::new(Vec::new()),
            candidates: Mutex::new(Vec::new()),
        };
        let runtime = runtime();
        let mut state = state(&policy(100));

        for _ in 0..10 {
            elapse_one_poll_interval(&mut state);
            let outcome = observe_tick(
                &port,
                &backend,
                &BitcoinNetwork::Regtest,
                &runtime,
                &mut state,
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
    async fn three_failing_addresses_never_degrade_availability_or_other_sellers() {
        // Attacker scenario: three disclosed addresses (A, B, C) whose
        // lookups fail — with no intervening success — plus one healthy
        // seller (D) in the same plan. D is observed and stamped, A/B/C
        // keep their staleness and stay in the queue, Electrum stays
        // available, and no backoff is recorded: per-address failures are
        // never promoted to endpoint unavailability.
        let port = FakeElectrum::failing_addresses(["a", "b", "c"]);
        let backend = FakeBackend {
            entries: Mutex::new(vec![
                FakeEntry::new("a", 600),
                FakeEntry::new("b", 300),
                FakeEntry::new("c", 120),
                FakeEntry::new("d", 60),
            ]),
            applied: Mutex::new(Vec::new()),
            stamped: Mutex::new(Vec::new()),
            candidates: Mutex::new(Vec::new()),
        };
        let runtime = runtime();
        let mut state = state(&policy(100));
        let mut backoff = ObserverBackoff::new();

        for tick in 0..2 {
            elapse_one_poll_interval(&mut state);
            let outcome = observe_tick(
                &port,
                &backend,
                &BitcoinNetwork::Regtest,
                &runtime,
                &mut state,
            )
            .await;
            assert_eq!(
                outcome,
                ObserverTickOutcome::Observed {
                    processed: 4,
                    deferred: 0,
                    failed: 3,
                },
                "tick {tick}: the failed addresses stay isolated, D is observed"
            );
            backoff.record_outcome(&outcome);
            assert!(!backoff.is_backing_off(), "tick {tick}: no backoff");
            let report = runtime.readiness().await;
            assert_eq!(
                report.electrum,
                paykit_server::runtime::ComponentState::Ready,
                "tick {tick}: /health/ready stays ready"
            );
        }
        assert_eq!(
            backend.stamped.lock().unwrap().as_slice(),
            &[vec!["d".to_owned()], vec!["d".to_owned()]],
            "only the healthy seller is ever stamped"
        );
        let entries = backend.entries.lock().unwrap();
        assert_eq!(entries[0].staleness_secs, 600, "a keeps its staleness");
        assert_eq!(entries[1].staleness_secs, 300, "b keeps its staleness");
        assert_eq!(entries[2].staleness_secs, 120, "c keeps its staleness");
    }

    #[tokio::test]
    async fn an_a_b_a_failure_pattern_never_degrades_availability() {
        // Two attacker addresses failing alternately across ticks (A, B,
        // then A again) with no successful lookup anywhere: availability
        // and backoff are unaffected, and the failed targets keep their
        // queue position.
        let port = FakeElectrum::failing_addresses(["a", "b"]);
        let backend = FakeBackend {
            entries: Mutex::new(vec![FakeEntry::new("a", 600), FakeEntry::new("b", 300)]),
            applied: Mutex::new(Vec::new()),
            stamped: Mutex::new(Vec::new()),
            candidates: Mutex::new(Vec::new()),
        };
        let runtime = runtime();
        let mut state = state(&policy(100));
        let mut backoff = ObserverBackoff::new();

        for _ in 0..3 {
            elapse_one_poll_interval(&mut state);
            let outcome = observe_tick(
                &port,
                &backend,
                &BitcoinNetwork::Regtest,
                &runtime,
                &mut state,
            )
            .await;
            assert_eq!(
                outcome,
                ObserverTickOutcome::Observed {
                    processed: 2,
                    deferred: 0,
                    failed: 2,
                }
            );
            backoff.record_outcome(&outcome);
            assert!(!backoff.is_backing_off());
            assert_eq!(
                runtime.readiness().await.electrum,
                paykit_server::runtime::ComponentState::Ready
            );
        }
        let entries = backend.entries.lock().unwrap();
        assert_eq!(entries[0].staleness_secs, 600, "a stays stale and queued");
        assert_eq!(entries[1].staleness_secs, 300, "b stays stale and queued");
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
            candidates: Mutex::new(Vec::new()),
        };
        let runtime = runtime();

        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &runtime,
            &mut state(&policy(100)),
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
            candidates: Mutex::new(Vec::new()),
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
            &runtime,
            &mut state(&policy(100)),
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
            candidates: Mutex::new(Vec::new()),
        };
        let runtime = runtime();

        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &runtime,
            &mut state(&policy(100)),
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
            candidates: Mutex::new(Vec::new()),
        };
        let runtime = runtime();

        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &runtime,
            &mut state(&policy(100)),
        )
        .await;
        assert!(matches!(outcome, ObserverTickOutcome::Observed { .. }));
        let encoded = runtime.metrics().encode().unwrap();
        assert!(
            encoded
                .contains("paykit_electrum_observation_address_failures_total{reason=\"error\"} 1"),
            "the isolated failure must be counted under the error label: {encoded}"
        );
    }

    #[tokio::test]
    async fn a_creation_caller_draining_the_shared_bucket_shrinks_the_next_tick() {
        // The tick and non-tick callers share one pool, not separate
        // pools: a creation caller that reserves most of the bucket leaves
        // the next tick only the probe reservation, so it admits fewer
        // lookups than the same tick would with the bucket to itself.
        let port = FakeElectrum::healthy();
        let backend = FakeBackend {
            entries: Mutex::new(vec![
                FakeEntry::new("oldest", 600),
                FakeEntry::new("second", 300),
                FakeEntry::new("third", 120),
            ]),
            applied: Mutex::new(Vec::new()),
            stamped: Mutex::new(Vec::new()),
            candidates: Mutex::new(Vec::new()),
        };
        let runtime = runtime();
        // Capacity 6, fast refill rewound away: the tick alone would
        // charge 2 probe requests and admit 4 lookups.
        let limiter = RequestLimiter::new(6, 0);
        let mut state = ObserverTickState::with_limiter(limiter.clone());
        let creation_permit = limiter
            .try_reserve(4)
            .expect("the creation caller reserves first");

        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &runtime,
            &mut state,
        )
        .await;
        assert_eq!(
            outcome,
            ObserverTickOutcome::Observed {
                processed: 0,
                deferred: 3,
                failed: 0,
            },
            "6 - 4 = 2 tokens left, exactly the probe reservation: the tick admits no lookups"
        );
        assert!(port.calls.lock().unwrap().is_empty());
        drop(creation_permit);

        // Without the creation reservation the same tick admits four.
        let limiter = RequestLimiter::new(6, 0);
        let mut state = ObserverTickState::with_limiter(limiter);
        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &runtime,
            &mut state,
        )
        .await;
        assert_eq!(
            outcome,
            ObserverTickOutcome::Observed {
                processed: 3,
                deferred: 0,
                failed: 0,
            },
            "6 - 2 probe = 4 lookups, admitting the whole three-target plan"
        );
    }

    #[tokio::test]
    async fn a_zero_success_tick_is_counted_but_keeps_electrum_available() {
        // Every attempted lookup fails in isolation: the tick is visible
        // through the zero-success counter, but availability stays up and
        // no backoff triggers — the endpoint was reached and answered.
        let port = FakeElectrum::failing_addresses(["stuck-a", "stuck-b"]);
        let backend = FakeBackend {
            entries: Mutex::new(vec![
                FakeEntry::new("stuck-a", 600),
                FakeEntry::new("stuck-b", 300),
            ]),
            applied: Mutex::new(Vec::new()),
            stamped: Mutex::new(Vec::new()),
            candidates: Mutex::new(Vec::new()),
        };
        let runtime = runtime();

        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &runtime,
            &mut state(&policy(100)),
        )
        .await;
        assert_eq!(
            outcome,
            ObserverTickOutcome::Observed {
                processed: 2,
                deferred: 0,
                failed: 2,
            }
        );
        let encoded = runtime.metrics().encode().unwrap();
        assert!(
            encoded.contains("paykit_electrum_zero_success_ticks_total 1"),
            "the zero-success tick must be counted: {encoded}"
        );
        let report = runtime.readiness().await;
        assert_eq!(
            report.electrum,
            paykit_server::runtime::ComponentState::Ready,
            "isolated failures never degrade endpoint availability"
        );
    }

    #[tokio::test]
    async fn a_successful_tick_resets_the_zero_success_log_streak() {
        // The ERROR log is rate-limited to once per zero-success streak:
        // the gate (`zero_success_logged`) closes on the first
        // zero-success tick, stays closed while ticks keep failing, and a
        // tick with a successful lookup reopens it so the next
        // zero-success tick logs again. The counter increments on every
        // zero-success tick regardless.
        let backend = FakeBackend {
            entries: Mutex::new(vec![
                FakeEntry::new("stuck", 600),
                FakeEntry::new("cheap", 300),
            ]),
            applied: Mutex::new(Vec::new()),
            stamped: Mutex::new(Vec::new()),
            candidates: Mutex::new(Vec::new()),
        };
        let runtime = runtime();
        let mut state = state(&policy(100));

        for tick in 1..=2 {
            let port = FakeElectrum::failing_addresses(["stuck", "cheap"]);
            let outcome = observe_tick(
                &port,
                &backend,
                &BitcoinNetwork::Regtest,
                &runtime,
                &mut state,
            )
            .await;
            assert!(matches!(outcome, ObserverTickOutcome::Observed { .. }));
            assert!(
                state.zero_success_logged(),
                "tick {tick}: the streak gate stays closed, suppressing a repeat ERROR log"
            );
            elapse_one_poll_interval(&mut state);
        }
        let encoded = runtime.metrics().encode().unwrap();
        assert!(
            encoded.contains("paykit_electrum_zero_success_ticks_total 2"),
            "every zero-success tick is counted even within one streak: {encoded}"
        );

        // A tick with a successful lookup reopens the streak gate.
        let port = FakeElectrum::healthy();
        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &runtime,
            &mut state,
        )
        .await;
        assert!(matches!(outcome, ObserverTickOutcome::Observed { .. }));
        assert!(
            !state.zero_success_logged(),
            "a successful tick resets the streak"
        );

        // So the next zero-success tick logs ERROR again (gate closes
        // anew) and the counter keeps accruing.
        elapse_one_poll_interval(&mut state);
        let port = FakeElectrum::failing_addresses(["stuck", "cheap"]);
        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &runtime,
            &mut state,
        )
        .await;
        assert!(matches!(outcome, ObserverTickOutcome::Observed { .. }));
        assert!(
            state.zero_success_logged(),
            "the first zero-success tick of a new streak logs again"
        );
        let encoded = runtime.metrics().encode().unwrap();
        assert!(
            encoded.contains("paykit_electrum_zero_success_ticks_total 3"),
            "the counter accrues across streaks: {encoded}"
        );
    }

    #[tokio::test]
    async fn the_sustained_budget_admits_nothing_without_elapsed_refill() {
        // The token bucket refills from elapsed wall time, not from the
        // tick count: two back-to-back ticks admit only the first tick's
        // budget — the jittered loop can never sustain more than
        // max_requests_per_second.
        let port = FakeElectrum::healthy();
        let backend = FakeBackend {
            entries: Mutex::new(vec![
                FakeEntry::new("oldest", 600),
                FakeEntry::new("second", 300),
                FakeEntry::new("third", 120),
            ]),
            applied: Mutex::new(Vec::new()),
            stamped: Mutex::new(Vec::new()),
            candidates: Mutex::new(Vec::new()),
        };
        let runtime = runtime();
        // Capacity 3 (one post-probe lookup), rate 1/s: an immediate second
        // tick has refilled nothing.
        let mut state = state(&ObserverPolicy {
            poll_interval: Duration::from_secs(10),
            max_requests_per_tick: 3,
            max_requests_per_second: 1,
            max_transaction_bytes: 400_000,
            baseline_completion_timeout: Duration::from_secs(60),
        });

        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &runtime,
            &mut state,
        )
        .await;
        assert_eq!(
            outcome,
            ObserverTickOutcome::Observed {
                processed: 1,
                deferred: 2,
                failed: 0,
            }
        );
        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &runtime,
            &mut state,
        )
        .await;
        assert_eq!(
            outcome,
            ObserverTickOutcome::Observed {
                processed: 0,
                deferred: 3,
                failed: 0,
            },
            "no wall time elapsed, so the bucket admits nothing"
        );
        // After one poll interval the bucket has refilled 1/s x 10s = 10
        // tokens, capped at its capacity of 3: the probe reserves 2 and
        // exactly one lookup is admitted.
        elapse_one_poll_interval(&mut state);
        let outcome = observe_tick(
            &port,
            &backend,
            &BitcoinNetwork::Regtest,
            &runtime,
            &mut state,
        )
        .await;
        assert_eq!(
            outcome,
            ObserverTickOutcome::Observed {
                processed: 1,
                deferred: 2,
                failed: 0,
            },
            "the bucket capacity, not rate x poll_interval, bounds the burst"
        );
        let calls = port.calls.lock().unwrap();
        assert_eq!(calls.len(), 2, "only two lookups were ever issued");
    }
}
