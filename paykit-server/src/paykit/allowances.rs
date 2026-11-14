//! Allowance intake: the server accepts, as the Allowee, the Allowance
//! proposals its invoiced readers leave on their links.
//!
//! Each read is one SDK call that accepts a bounded number of a reader's
//! pending proposals in one transaction, with work bounded by a per-link
//! record cap rather than the reader's history. The intake still runs on its
//! own worker, never in an outbox handoff or the shared transport loop, one
//! task per Creator, and bounds how often and for how long it reads each
//! reader. It only queues acceptances; the transport worker delivers them.

use std::{
    collections::{HashMap, HashSet},
    sync::Mutex as StdMutex,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use paykit_sdk::{
    LinkedPeerState, MAX_PENDING_ALLOWANCE_LINK_RECORDS, PaykitSdkError,
    PendingAllowanceAcceptance, PubkyPublicKey, StorageAdapter,
};
use tokio::sync::Mutex as TokioMutex;
use tracing::{info, warn};
use uuid::Uuid;

use super::{PaykitAdapter, sdk_error_label};
use crate::{
    domain::locks::{ReaderPubky, parse_reader},
    persistence::InvoiceStore,
};

/// Acceptances queued per read. Each one is a durable outbound message, so a
/// reader that floods the link cannot turn one read into unbounded output; a
/// later read accepts the rest.
const MAX_ALLOWANCE_ACCEPTANCES_PER_READ: usize = 4;

/// Records one Acceptance adds to its link: the outbound Acceptance and the
/// reader's Delivery Confirmation of it.
const RECORDS_PER_ACCEPTANCE: usize = 2;

/// Acceptances one read may queue on a link holding `records` records: never
/// so many that the server's own Acceptances, and their confirmations, take
/// the link past the SDK's record cap, where automatic acceptance stops and
/// the proposals left are for manual acceptance.
fn acceptance_limit(records: usize) -> usize {
    (MAX_PENDING_ALLOWANCE_LINK_RECORDS.saturating_sub(records) / RECORDS_PER_ACCEPTANCE)
        .min(MAX_ALLOWANCE_ACCEPTANCES_PER_READ)
}

/// Least time between two reads of one reader's Allowances.
pub const ALLOWANCE_INTAKE_COOLDOWN: Duration = Duration::from_secs(10);

/// A reader whose read took `d` is read again no sooner than `d` times this
/// after that read began, so the intake spends at most about a tenth of its
/// time on any one reader.
const ALLOWANCE_INTAKE_SPACING_FACTOR: u32 = 10;

/// Longest wait for the Creator lock before one acceptance. Giving up starts
/// no SDK call, so the read ends as a failure with nothing to clean up.
const ALLOWANCE_INTAKE_LOCK_WAIT: Duration = Duration::from_secs(20);

/// A pass starts no new read this long after it began, far above any pass
/// that makes progress. A read already started is never cut short: each one
/// is an SDK mutation, and dropping it mid-flight would skip its homeserver
/// unlock and leave state unconfirmed. The server's Pubky request timeout
/// bounds a read on a stalled homeserver instead.
pub const ALLOWANCE_INTAKE_PASS_DEADLINE: Duration = Duration::from_secs(600);

/// A Creator's pass starts no new read after this much time spent reading;
/// the readers left over are read on the next pass. Finding the due readers
/// does not count, and the first read always starts, so every pass reads at
/// least one due reader.
const ALLOWANCE_INTAKE_READ_BUDGET: Duration = Duration::from_secs(5);

/// Decides when a reader's Allowances are read. A read is worth doing only
/// when the reader's link holds stream items an earlier read did not cover,
/// and no sooner than the cooldown, or ten times the last read's scan,
/// after the last read began.
#[derive(Debug)]
pub struct AllowanceIntake {
    cooldown: Duration,
    readers: StdMutex<HashMap<(Uuid, PubkyPublicKey), ReaderIntake>>,
}

#[derive(Debug, Default)]
struct ReaderIntake {
    /// Newest stream item an earlier read covered completely.
    covered_through: Option<u64>,
    last_started: Option<Instant>,
    last_scan: Duration,
}

/// A read that is due, to be reported back with [`AllowanceIntake::finish`].
struct IntakeTicket {
    creator_id: Uuid,
    reader: PubkyPublicKey,
    newest_stream_item_id: u64,
}

impl AllowanceIntake {
    pub fn new(cooldown: Duration) -> Self {
        Self {
            cooldown,
            readers: StdMutex::new(HashMap::new()),
        }
    }

    fn with_reader<T>(
        &self,
        creator_id: Uuid,
        reader: &PubkyPublicKey,
        f: impl FnOnce(&mut ReaderIntake) -> T,
    ) -> T {
        let mut readers = self
            .readers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        f(readers.entry((creator_id, reader.clone())).or_default())
    }

    /// Whether the reader's link, whose newest stream item is `newest`, is due
    /// for a read at `now`.
    fn is_due(
        &self,
        creator_id: Uuid,
        reader: &PubkyPublicKey,
        newest: Option<u64>,
        now: Instant,
    ) -> bool {
        let Some(newest) = newest else {
            return false;
        };
        self.with_reader(creator_id, reader, |state| {
            let spacing = self
                .cooldown
                .max(state.last_scan * ALLOWANCE_INTAKE_SPACING_FACTOR);
            state.covered_through.is_none_or(|covered| newest > covered)
                && state
                    .last_started
                    .is_none_or(|started| now.saturating_duration_since(started) >= spacing)
        })
    }

    /// Starts a due read. It counts against the spacing at once, so a failed
    /// read is not retried sooner, and until it is finished it counts as a
    /// scan that took the whole pass deadline: a read that never finishes, as
    /// after a panic, is spaced out by ten times that. The deadline itself
    /// never cuts a running read short; it only stops new reads starting.
    fn begin(
        &self,
        creator_id: Uuid,
        reader: &PubkyPublicKey,
        newest: Option<u64>,
        now: Instant,
    ) -> Option<IntakeTicket> {
        if !self.is_due(creator_id, reader, newest, now) {
            return None;
        }
        self.with_reader(creator_id, reader, |state| {
            state.last_started = Some(now);
            state.last_scan = ALLOWANCE_INTAKE_PASS_DEADLINE;
        });
        Some(IntakeTicket {
            creator_id,
            reader: reader.clone(),
            newest_stream_item_id: newest?,
        })
    }

    /// When the reader's last read started, if it was ever read.
    fn last_started(&self, creator_id: Uuid, reader: &PubkyPublicKey) -> Option<Instant> {
        self.with_reader(creator_id, reader, |state| state.last_started)
    }

    /// Records a finished read and how long its scan took. When it failed or
    /// left proposals behind the per-read limit, the same items stay due for
    /// the next read.
    fn finish(&self, ticket: IntakeTicket, drained: bool, scan: Duration) {
        self.with_reader(ticket.creator_id, &ticket.reader, |state| {
            state.last_scan = scan;
            if drained {
                state.covered_through = Some(ticket.newest_stream_item_id);
            }
        });
    }
}

/// Orders ready Creators for the intake's bounded task slots: a Creator never
/// started goes first, then the one whose last pass started longest ago. When
/// slow passes hold every slot, each Creator still gets a turn.
#[derive(Debug, Default)]
pub struct IntakeTurns {
    last_started: HashMap<Uuid, u64>,
    next: u64,
}

impl IntakeTurns {
    /// The ready Creators, least recently started first. A Creator that is no
    /// longer ready is forgotten.
    pub fn order(&mut self, mut ready: Vec<Uuid>) -> Vec<Uuid> {
        let current = ready.iter().copied().collect::<HashSet<_>>();
        self.last_started
            .retain(|creator, _| current.contains(creator));
        ready.sort_by_key(|creator| self.last_started.get(creator).copied());
        ready
    }

    /// Records that `creator`'s pass started.
    pub fn started(&mut self, creator: Uuid) {
        self.last_started.insert(creator, self.next);
        self.next += 1;
    }
}

impl PaykitAdapter {
    /// One intake pass over this Creator's linked readers. Only readers this
    /// Creator has invoiced are read: a Linked peer that another App on the
    /// shared identity linked is left to that App. A peer is checked again on
    /// every pass, and nothing it sent counts as covered until it is invoiced,
    /// so a first invoice makes the proposals it already sent due. Read and
    /// acceptance failures are logged per reader and retried after the spacing.
    ///
    /// Returns how many acceptances it queued. It sends none of them: the
    /// caller wakes the transport worker, which delivers them.
    pub async fn take_in_allowances(
        &self,
        intake: &AllowanceIntake,
        invoices: &InvoiceStore,
        keep_reading: &(dyn Fn() -> bool + Sync),
    ) -> paykit_sdk::Result<usize> {
        let now = Instant::now();
        let linked = {
            let _guard = self.mutation_lock.lock().await;
            self.sdk.linked_peers().await?
        }
        .into_iter()
        .filter(|peer| peer.state == LinkedPeerState::Linked)
        .map(|peer| peer.counterparty)
        .collect::<Vec<_>>();
        if linked.is_empty() {
            return Ok(0);
        }
        // Eligibility first: the stream of a peer this Creator never invoiced
        // is not read at all.
        let candidates = linked.iter().filter_map(reader_of).collect::<Vec<_>>();
        let invoiced = invoices
            .invoiced_readers(self.creator_id, &candidates)
            .await
            .map_err(|_| PaykitSdkError::Storage {
                context: "invoiced readers unavailable".into(),
                source: None,
            })?
            .iter()
            .map(ReaderPubky::to_string)
            .collect::<HashSet<_>>();
        let eligible = linked
            .into_iter()
            .filter(|peer| {
                reader_of(peer).is_some_and(|reader| invoiced.contains(&reader.to_string()))
            })
            .collect::<Vec<_>>();
        if eligible.is_empty() {
            return Ok(0);
        }
        let activity = self.link_activity(&eligible).await?;
        let readers = eligible
            .into_iter()
            .filter_map(|peer| {
                let (newest, limit) = *activity.get(&peer)?;
                intake
                    .is_due(self.creator_id, &peer, Some(newest), now)
                    .then_some((peer, newest, limit))
            })
            .collect::<Vec<_>>();
        if readers.is_empty() {
            return Ok(0);
        }
        Ok(read_readers(
            self,
            &self.mutation_lock,
            intake,
            self.creator_id,
            readers,
            ReadLimits {
                budget: ALLOWANCE_INTAKE_READ_BUDGET,
                lock_wait: ALLOWANCE_INTAKE_LOCK_WAIT,
            },
            keep_reading,
        )
        .await)
    }

    /// Each link's newest stream item, and how many acceptances a read of it
    /// may queue under the SDK's record cap. The cap count visits no record,
    /// and a link with no headroom is left out before its items are read, so
    /// the items read per link are bounded by the cap.
    async fn link_activity(
        &self,
        linked: &[PubkyPublicKey],
    ) -> paykit_sdk::Result<HashMap<PubkyPublicKey, (u64, usize)>> {
        let linked = linked.to_vec();
        self.storage
            .transaction(move |transaction| {
                Ok(linked
                    .into_iter()
                    .filter_map(|peer| {
                        let records = transaction
                            .link_record_count_up_to(&peer, MAX_PENDING_ALLOWANCE_LINK_RECORDS + 1);
                        let limit = acceptance_limit(records);
                        if limit == 0 {
                            return None;
                        }
                        let newest = transaction
                            .private_stream_items(&peer)
                            .iter()
                            .map(|item| item.stream_item_id)
                            .max()?;
                        Some((peer, (newest, limit)))
                    })
                    .collect())
            })
            .await
    }
}

/// The Locks Reader identity of a linked peer, in the canonical form invoice
/// admission hashes.
pub(super) fn reader_of(peer: &PubkyPublicKey) -> Option<ReaderPubky> {
    parse_reader(&format!("pubky{peer}")).ok()
}

/// What the intake does on one reader's link.
#[async_trait]
trait AllowanceLink: Send + Sync {
    /// Records the reader's link holds, up to one past the SDK's cap. The
    /// count visits no record.
    async fn link_records(&self, reader: &PubkyPublicKey) -> paykit_sdk::Result<usize>;

    /// Queues acceptances of up to `limit` of the reader's pending proposals,
    /// oldest first, in one SDK transaction. The caller serializes it with the
    /// Creator's other mutations.
    async fn accept_pending(
        &self,
        reader: &PubkyPublicKey,
        limit: usize,
    ) -> paykit_sdk::Result<LinkAcceptance>;
}

/// What one bounded acceptance call did on a reader's link.
#[derive(Debug, PartialEq, Eq)]
struct LinkAcceptance {
    accepted: usize,
    /// Whether pending proposals remain beyond the limit.
    more_pending: bool,
}

struct IntakeRead {
    accepted: usize,
    /// How long the acceptance call took, up to its failure if it failed. It
    /// spaces out the next read on every outcome.
    scan: Duration,
    /// Whether no proposal is left waiting behind the per-read limit, or why
    /// the read stopped.
    result: paykit_sdk::Result<bool>,
}

/// How long a pass keeps starting reads, and how long an acceptance waits for
/// the Creator lock.
#[derive(Clone, Copy)]
struct ReadLimits {
    budget: Duration,
    lock_wait: Duration,
}

/// Reads the due readers, `(reader, newest stream item, acceptance limit)`, least recently read
/// first, until `budget` has passed since the first read started; the first
/// read always starts. A reader left with proposals behind the per-read limit
/// therefore goes behind the others next pass. No read starts once
/// `keep_reading` turns false, as on shutdown. Returns how many acceptances it
/// queued.
async fn read_readers<L: AllowanceLink + ?Sized>(
    link: &L,
    mutation_lock: &TokioMutex<()>,
    intake: &AllowanceIntake,
    creator_id: Uuid,
    mut readers: Vec<(PubkyPublicKey, u64, usize)>,
    limits: ReadLimits,
    keep_reading: &(dyn Fn() -> bool + Sync),
) -> usize {
    let ReadLimits { budget, lock_wait } = limits;
    readers.sort_by_key(|(peer, _, _)| intake.last_started(creator_id, peer));
    let mut reading_since = None::<Instant>;
    let mut queued = 0;
    for (peer, newest, limit) in readers {
        if !keep_reading() || reading_since.is_some_and(|since| since.elapsed() >= budget) {
            break;
        }
        let now = Instant::now();
        let Some(ticket) = intake.begin(creator_id, &peer, Some(newest), now) else {
            continue;
        };
        reading_since.get_or_insert(now);
        let read = accept_proposals(link, mutation_lock, &peer, limit, lock_wait).await;
        if read.accepted > 0 {
            info!(
                accepted = read.accepted,
                "accepted Paykit Allowance proposals"
            );
        }
        queued += read.accepted;
        let drained = match read.result {
            Ok(drained) => drained,
            Err(error) => {
                warn!(
                    stage = "allowance_intake",
                    cause = sdk_error_label(&error),
                    "Paykit Allowance intake failed; retried after the spacing"
                );
                false
            }
        };
        intake.finish(ticket, drained, read.scan);
    }
    queued
}

/// Accepts up to `limit` pending proposals in one SDK call, under the Creator
/// mutation lock. The call's work is bounded by the SDK's per-link record cap,
/// so other Creator work waits at most that long. The link's headroom is
/// counted again under the lock, since another mutation may have added
/// records while this read waited for it. Giving up on the lock starts no SDK
/// call, and neither does a link at the cap: its proposals are left for
/// manual acceptance and it counts as read.
async fn accept_proposals<L: AllowanceLink + ?Sized>(
    link: &L,
    mutation_lock: &TokioMutex<()>,
    reader: &PubkyPublicKey,
    limit: usize,
    lock_wait: Duration,
) -> IntakeRead {
    let at_cap = || {
        warn!(
            stage = "allowance_intake",
            cause = "link_history_at_cap",
            "Paykit Allowance link at the record cap; not accepted automatically"
        );
        IntakeRead {
            accepted: 0,
            scan: Duration::ZERO,
            result: Ok(true),
        }
    };
    if limit == 0 {
        return at_cap();
    }
    let Ok(_guard) = tokio::time::timeout(lock_wait, mutation_lock.lock()).await else {
        return IntakeRead {
            accepted: 0,
            scan: Duration::ZERO,
            result: Err(PaykitSdkError::Transport {
                context: "Creator lock wait timed out".into(),
                source: None,
            }),
        };
    };
    let started = Instant::now();
    let limit = match link.link_records(reader).await {
        Ok(records) => limit.min(acceptance_limit(records)),
        Err(error) => {
            return IntakeRead {
                accepted: 0,
                scan: started.elapsed(),
                result: Err(error),
            };
        }
    };
    if limit == 0 {
        return at_cap();
    }
    let outcome = link.accept_pending(reader, limit).await;
    let scan = started.elapsed();
    match outcome {
        Ok(LinkAcceptance {
            accepted,
            more_pending,
        }) => IntakeRead {
            accepted,
            scan,
            result: Ok(!more_pending),
        },
        Err(error) => IntakeRead {
            accepted: 0,
            scan,
            result: Err(error),
        },
    }
}

#[async_trait]
impl AllowanceLink for PaykitAdapter {
    async fn link_records(&self, reader: &PubkyPublicKey) -> paykit_sdk::Result<usize> {
        let reader = reader.clone();
        self.storage
            .transaction(move |transaction| {
                Ok(transaction
                    .link_record_count_up_to(&reader, MAX_PENDING_ALLOWANCE_LINK_RECORDS + 1))
            })
            .await
    }

    async fn accept_pending(
        &self,
        reader: &PubkyPublicKey,
        limit: usize,
    ) -> paykit_sdk::Result<LinkAcceptance> {
        let outcome = self
            .sdk
            .accept_pending_allowance_proposals(reader.clone(), limit)
            .await?;
        link_acceptance(outcome)
    }
}

/// A link over the SDK's record cap is left alone: nothing on it is accepted
/// automatically, and it counts as read until new items arrive. An outcome
/// this server does not know fails the read, so the link stays due and is
/// retried after the spacing.
fn link_acceptance(outcome: PendingAllowanceAcceptance) -> paykit_sdk::Result<LinkAcceptance> {
    match outcome {
        PendingAllowanceAcceptance::Accepted {
            records,
            more_pending,
        } => Ok(LinkAcceptance {
            accepted: records.len(),
            more_pending,
        }),
        PendingAllowanceAcceptance::LinkHistoryTooLarge { .. } => {
            warn!(
                stage = "allowance_intake",
                cause = "link_history_too_large",
                "Paykit Allowance link over the record cap; not accepted automatically"
            );
            Ok(LinkAcceptance {
                accepted: 0,
                more_pending: false,
            })
        }
        _ => Err(PaykitSdkError::Protocol {
            context: "unknown Allowance acceptance outcome".into(),
            source: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    const READER: &str = "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo";
    const LOCK_WAIT: Duration = Duration::from_secs(5);

    fn reader() -> PubkyPublicKey {
        PubkyPublicKey::from_raw_or_app_key(READER).unwrap()
    }

    fn other_reader() -> PubkyPublicKey {
        PubkyPublicKey::from_raw_or_app_key(
            "pubky5jsjx1o6fzu6aeeo697r3i5rx15zq41kikcye8wtwdqm4nb4tryo",
        )
        .unwrap()
    }

    #[test]
    fn a_linked_peer_maps_to_the_reader_identity_invoices_hash() {
        // Admission hashes `ReaderPubky::to_string()`; the intake must look the
        // same identity up under the same bytes.
        let admitted = parse_reader(&format!("pubky{READER}")).unwrap();
        let peer = PubkyPublicKey::from_raw_or_app_key(admitted.to_string()).unwrap();
        assert_eq!(reader_of(&peer).unwrap().to_string(), admitted.to_string());
        assert_eq!(
            reader_of(&reader()).unwrap().to_string(),
            admitted.to_string()
        );
    }

    #[test]
    fn allowances_are_read_only_when_the_link_received_new_items() {
        let intake = AllowanceIntake::new(Duration::from_secs(10));
        let creator = Uuid::new_v4();
        let start = Instant::now();

        // Nothing received on the link: nothing to read.
        assert!(intake.begin(creator, &reader(), None, start).is_none());

        let ticket = intake.begin(creator, &reader(), Some(5), start).unwrap();
        intake.finish(ticket, true, Duration::ZERO);

        // The same items again, long after the cooldown: still nothing to read.
        let later = start + Duration::from_secs(3_600);
        assert!(intake.begin(creator, &reader(), Some(5), later).is_none());
        assert!(intake.begin(creator, &reader(), Some(6), later).is_some());
    }

    #[test]
    fn a_reader_is_read_at_most_once_per_cooldown() {
        let intake = AllowanceIntake::new(Duration::from_secs(10));
        let creator = Uuid::new_v4();
        let start = Instant::now();

        let ticket = intake.begin(creator, &reader(), Some(1), start).unwrap();
        intake.finish(ticket, true, Duration::ZERO);

        // A flood of new items does not make the next read come sooner.
        for (seconds, newest) in [(1, 10), (5, 500), (9, 90_000)] {
            let now = start + Duration::from_secs(seconds);
            assert!(
                intake
                    .begin(creator, &reader(), Some(newest), now)
                    .is_none()
            );
        }
        let after = start + Duration::from_secs(10);
        assert!(
            intake
                .begin(creator, &reader(), Some(90_000), after)
                .is_some()
        );
    }

    #[test]
    fn a_slow_scan_spaces_the_next_read_out_to_ten_times_its_duration() {
        let intake = AllowanceIntake::new(Duration::from_secs(10));
        let creator = Uuid::new_v4();
        let start = Instant::now();

        // A read that takes 4 s: the next read waits 40 s.
        let ticket = intake.begin(creator, &reader(), Some(1), start).unwrap();
        intake.finish(ticket, true, Duration::from_secs(4));
        let early = start + Duration::from_secs(39);
        assert!(intake.begin(creator, &reader(), Some(2), early).is_none());
        let due = start + Duration::from_secs(40);
        let ticket = intake.begin(creator, &reader(), Some(2), due).unwrap();

        // A quick scan brings it back to the cooldown.
        intake.finish(ticket, true, Duration::ZERO);
        let next = due + Duration::from_secs(10);
        assert!(intake.begin(creator, &reader(), Some(3), next).is_some());
    }

    #[test]
    fn a_failed_or_unfinished_read_is_retried_after_the_cooldown() {
        let intake = AllowanceIntake::new(Duration::from_secs(10));
        let creator = Uuid::new_v4();
        let start = Instant::now();
        let after = start + Duration::from_secs(10);

        // A failed read counted against the cooldown and covers nothing.
        let ticket = intake.begin(creator, &reader(), Some(4), start).unwrap();
        assert!(intake.begin(creator, &reader(), Some(4), start).is_none());
        intake.finish(ticket, false, Duration::ZERO);
        let ticket = intake.begin(creator, &reader(), Some(4), after).unwrap();

        // A read that left proposals behind the per-read limit keeps the items due.
        intake.finish(ticket, false, Duration::ZERO);
        let again = after + Duration::from_secs(10);
        let ticket = intake.begin(creator, &reader(), Some(4), again).unwrap();
        intake.finish(ticket, true, Duration::ZERO);
        let last = again + Duration::from_secs(10);
        assert!(intake.begin(creator, &reader(), Some(4), last).is_none());
    }

    #[test]
    fn a_link_skipped_before_its_first_invoice_stays_due() {
        let intake = AllowanceIntake::new(Duration::from_secs(10));
        let creator = Uuid::new_v4();
        let now = Instant::now();

        // A pass that finds the peer not yet invoiced, including one whose
        // invoice commits right after the lookup, checks only whether it is
        // due. Its proposal stays due until a pass finds it invoiced.
        for pass in 0..3 {
            let at = now + Duration::from_secs(pass);
            assert!(intake.is_due(creator, &reader(), Some(8), at));
        }
        assert!(intake.begin(creator, &reader(), Some(8), now).is_some());
    }

    #[test]
    fn readers_and_creators_are_scheduled_independently() {
        let intake = AllowanceIntake::new(Duration::from_secs(10));
        let (creator, other_creator) = (Uuid::new_v4(), Uuid::new_v4());
        let now = Instant::now();

        assert!(intake.begin(creator, &reader(), Some(1), now).is_some());
        assert!(
            intake
                .begin(creator, &other_reader(), Some(1), now)
                .is_some()
        );
        assert!(
            intake
                .begin(other_creator, &reader(), Some(1), now)
                .is_some()
        );
    }

    #[test]
    fn creators_take_turns_least_recently_started_first() {
        let mut turns = IntakeTurns::default();
        let creators = [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];

        // Two slots: the first two start, and the third goes first next time.
        let order = turns.order(creators.to_vec());
        turns.started(order[0]);
        turns.started(order[1]);
        assert_eq!(turns.order(creators.to_vec())[0], order[2]);
        turns.started(order[2]);
        assert_eq!(turns.order(creators.to_vec()), order);

        // A Creator that is no longer ready is forgotten; if it comes back it
        // counts as never started.
        turns.order(vec![order[1], order[2]]);
        assert_eq!(turns.order(creators.to_vec())[0], order[0]);
    }

    #[tokio::test]
    async fn every_pass_reads_a_due_reader_even_with_no_budget_left() {
        let lock = TokioMutex::new(());
        let intake = AllowanceIntake::new(Duration::from_secs(10));
        let creator = Uuid::new_v4();
        let link = ReadyLink::default();
        let readers = vec![
            (reader(), 1, MAX_ALLOWANCE_ACCEPTANCES_PER_READ),
            (other_reader(), 1, MAX_ALLOWANCE_ACCEPTANCES_PER_READ),
        ];

        // However long finding the due readers took, a pass reads one reader;
        // with no budget, only one. The next pass reads the other.
        for expected in [reader(), other_reader()] {
            let queued = read_readers(
                &link,
                &lock,
                &intake,
                creator,
                readers.clone(),
                ReadLimits {
                    budget: Duration::ZERO,
                    lock_wait: LOCK_WAIT,
                },
                &|| true,
            )
            .await;
            assert_eq!(queued, 1);
            assert_eq!(link.scans.lock().unwrap().last(), Some(&expected));
        }
        assert_eq!(link.scans.lock().unwrap().len(), 2);

        // With budget, one pass reads every due reader.
        let intake = AllowanceIntake::new(Duration::from_secs(10));
        let queued = read_readers(
            &link,
            &lock,
            &intake,
            creator,
            readers,
            ReadLimits {
                budget: Duration::from_secs(5),
                lock_wait: LOCK_WAIT,
            },
            &|| true,
        )
        .await;
        assert_eq!(queued, 2);
    }

    #[tokio::test]
    async fn a_reader_left_with_a_backlog_goes_behind_the_others() {
        let lock = TokioMutex::new(());
        // No cooldown: the backlogged reader stays due on every pass.
        let intake = AllowanceIntake::new(Duration::ZERO);
        let creator = Uuid::new_v4();
        let link = ReadyLink {
            backlog: HashMap::from([(reader(), MAX_ALLOWANCE_ACCEPTANCES_PER_READ * 3)]),
            ..ReadyLink::default()
        };
        let readers = vec![
            (reader(), 1, MAX_ALLOWANCE_ACCEPTANCES_PER_READ),
            (other_reader(), 1, MAX_ALLOWANCE_ACCEPTANCES_PER_READ),
        ];

        // One read per pass. The backlogged reader is read first, is not
        // drained, and the next pass reads the other reader before it again.
        for _ in 0..2 {
            read_readers(
                &link,
                &lock,
                &intake,
                creator,
                readers.clone(),
                ReadLimits {
                    budget: Duration::ZERO,
                    lock_wait: LOCK_WAIT,
                },
                &|| true,
            )
            .await;
            // Past the scan's spacing: the backlogged reader is due again.
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(intake.is_due(creator, &reader(), Some(1), Instant::now()));
        }
        assert_eq!(*link.scans.lock().unwrap(), [reader(), other_reader()]);
    }

    #[tokio::test]
    async fn an_acceptance_gives_up_on_a_held_creator_lock_without_calling_the_sdk() {
        const SHORT: Duration = Duration::from_millis(100);
        let lock = Arc::new(TokioMutex::new(()));
        let link = SlowLink::new(&lock, 1);
        link.call_release.notify_one();
        let held = lock.clone().lock_owned().await;

        let read = tokio::time::timeout(
            Duration::from_secs(5),
            accept_proposals(
                &link,
                &lock,
                &reader(),
                MAX_ALLOWANCE_ACCEPTANCES_PER_READ,
                SHORT,
            ),
        )
        .await
        .expect("the held lock held the read");

        assert!(matches!(read.result, Err(PaykitSdkError::Transport { .. })));
        assert_eq!(read.accepted, 0);
        // No SDK call started, so none was cut short.
        assert!(link.lock_held_during_calls.lock().unwrap().is_empty());
        drop(held);
    }

    #[test]
    fn a_read_that_never_reports_back_is_spaced_out_by_the_pass_deadline() {
        let intake = AllowanceIntake::new(Duration::from_secs(10));
        let creator = Uuid::new_v4();
        let start = Instant::now();

        // Cut off by the pass deadline or a panic: no finish.
        let _ticket = intake.begin(creator, &reader(), Some(1), start).unwrap();

        let spacing = ALLOWANCE_INTAKE_PASS_DEADLINE * ALLOWANCE_INTAKE_SPACING_FACTOR;
        let early = start + spacing - Duration::from_secs(1);
        assert!(!intake.is_due(creator, &reader(), Some(2), early));
        assert!(intake.is_due(creator, &reader(), Some(2), start + spacing));
    }

    #[tokio::test]
    async fn no_read_starts_once_the_intake_is_told_to_stop() {
        let lock = TokioMutex::new(());
        let intake = AllowanceIntake::new(Duration::from_secs(10));
        let link = ReadyLink::default();

        let queued = read_readers(
            &link,
            &lock,
            &intake,
            Uuid::new_v4(),
            vec![(reader(), 1, MAX_ALLOWANCE_ACCEPTANCES_PER_READ)],
            ReadLimits {
                budget: Duration::from_secs(5),
                lock_wait: LOCK_WAIT,
            },
            &|| false,
        )
        .await;

        assert_eq!(queued, 0);
        assert!(link.scans.lock().unwrap().is_empty());
    }

    /// A link with one pending proposal on every scan, or `backlog` for a
    /// reader listed there.
    #[derive(Default)]
    struct ReadyLink {
        scans: StdMutex<Vec<PubkyPublicKey>>,
        backlog: HashMap<PubkyPublicKey, usize>,
    }

    #[async_trait]
    impl AllowanceLink for ReadyLink {
        async fn link_records(&self, _reader: &PubkyPublicKey) -> paykit_sdk::Result<usize> {
            Ok(0)
        }

        async fn accept_pending(
            &self,
            reader: &PubkyPublicKey,
            limit: usize,
        ) -> paykit_sdk::Result<LinkAcceptance> {
            self.scans.lock().unwrap().push(reader.clone());
            let pending = self.backlog.get(reader).copied().unwrap_or(1);
            Ok(LinkAcceptance {
                accepted: pending.min(limit),
                more_pending: pending > limit,
            })
        }
    }

    /// A link whose acceptance call can be held in flight and that reports
    /// whether the Creator mutation lock was held during each call.
    struct SlowLink {
        lock: Arc<TokioMutex<()>>,
        pending: usize,
        call_entered: tokio::sync::Notify,
        call_release: tokio::sync::Notify,
        lock_held_during_calls: StdMutex<Vec<bool>>,
        call_takes: Duration,
        fail: bool,
    }

    impl SlowLink {
        fn new(lock: &Arc<TokioMutex<()>>, pending: usize) -> Self {
            Self {
                lock: lock.clone(),
                pending,
                call_entered: tokio::sync::Notify::new(),
                call_release: tokio::sync::Notify::new(),
                lock_held_during_calls: StdMutex::new(Vec::new()),
                call_takes: Duration::ZERO,
                fail: false,
            }
        }
    }

    #[async_trait]
    impl AllowanceLink for SlowLink {
        async fn link_records(&self, _reader: &PubkyPublicKey) -> paykit_sdk::Result<usize> {
            Ok(0)
        }

        async fn accept_pending(
            &self,
            _reader: &PubkyPublicKey,
            limit: usize,
        ) -> paykit_sdk::Result<LinkAcceptance> {
            self.lock_held_during_calls
                .lock()
                .unwrap()
                .push(self.lock.try_lock().is_err());
            self.call_entered.notify_one();
            self.call_release.notified().await;
            tokio::time::sleep(self.call_takes).await;
            if self.fail {
                return Err(PaykitSdkError::Transport {
                    context: "acceptances not stored".into(),
                    source: None,
                });
            }
            Ok(LinkAcceptance {
                accepted: self.pending.min(limit),
                more_pending: self.pending > limit,
            })
        }
    }

    #[tokio::test]
    async fn one_bounded_call_holds_the_creator_lock_and_frees_it_after() {
        let lock = Arc::new(TokioMutex::new(()));
        let link = Arc::new(SlowLink::new(&lock, 1_000));
        let intake = tokio::spawn({
            let (link, lock) = (link.clone(), lock.clone());
            async move {
                accept_proposals(
                    link.as_ref(),
                    &lock,
                    &reader(),
                    MAX_ALLOWANCE_ACCEPTANCES_PER_READ,
                    LOCK_WAIT,
                )
                .await
            }
        });

        // The call mutates the Creator's state, so it runs under the lock.
        link.call_entered.notified().await;
        assert!(lock.try_lock().is_err());

        link.call_release.notify_one();
        let outcome = intake.await.unwrap();

        assert_eq!(*link.lock_held_during_calls.lock().unwrap(), [true]);
        assert_eq!(outcome.accepted, MAX_ALLOWANCE_ACCEPTANCES_PER_READ);
        assert!(!outcome.result.unwrap());
        assert!(lock.try_lock().is_ok());
    }

    #[tokio::test]
    async fn the_intake_accepts_everything_pending_up_to_its_limit() {
        for (pending, accepted, drained) in [
            (0, 0, true),
            (1, 1, true),
            (
                MAX_ALLOWANCE_ACCEPTANCES_PER_READ,
                MAX_ALLOWANCE_ACCEPTANCES_PER_READ,
                true,
            ),
            (
                MAX_ALLOWANCE_ACCEPTANCES_PER_READ + 1,
                MAX_ALLOWANCE_ACCEPTANCES_PER_READ,
                false,
            ),
        ] {
            let lock = Arc::new(TokioMutex::new(()));
            let link = SlowLink::new(&lock, pending);
            link.call_release.notify_one();

            let outcome = accept_proposals(
                &link,
                &lock,
                &reader(),
                MAX_ALLOWANCE_ACCEPTANCES_PER_READ,
                LOCK_WAIT,
            )
            .await;

            assert_eq!(
                (outcome.accepted, outcome.result.unwrap()),
                (accepted, drained)
            );
        }
    }

    #[tokio::test]
    async fn a_failed_acceptance_ends_the_read_and_frees_the_lock() {
        let lock = Arc::new(TokioMutex::new(()));
        let mut link = SlowLink::new(&lock, 3);
        link.fail = true;
        link.call_release.notify_one();

        let read = accept_proposals(
            &link,
            &lock,
            &reader(),
            MAX_ALLOWANCE_ACCEPTANCES_PER_READ,
            LOCK_WAIT,
        )
        .await;

        assert!(matches!(read.result, Err(PaykitSdkError::Transport { .. })));
        assert_eq!(read.accepted, 0);
        assert_eq!(link.lock_held_during_calls.lock().unwrap().len(), 1);
        assert!(lock.try_lock().is_ok());
    }

    #[tokio::test]
    async fn a_failed_read_is_spaced_out_by_the_time_its_call_took() {
        const CALL: Duration = Duration::from_millis(200);
        let lock = Arc::new(TokioMutex::new(()));
        let mut link = SlowLink::new(&lock, 3);
        link.call_takes = CALL;
        link.fail = true;
        link.call_release.notify_one();
        let intake = AllowanceIntake::new(Duration::ZERO);
        let creator = Uuid::new_v4();
        let start = Instant::now();
        let ticket = intake.begin(creator, &reader(), Some(1), start).unwrap();

        let read = accept_proposals(
            &link,
            &lock,
            &reader(),
            MAX_ALLOWANCE_ACCEPTANCES_PER_READ,
            LOCK_WAIT,
        )
        .await;
        assert!(read.result.is_err());
        assert!(read.scan >= CALL, "{:?}", read.scan);
        intake.finish(ticket, false, read.scan);

        let spacing = read.scan * ALLOWANCE_INTAKE_SPACING_FACTOR;
        let early = start + spacing - Duration::from_millis(1);
        assert!(intake.begin(creator, &reader(), Some(1), early).is_none());
        assert!(
            intake
                .begin(creator, &reader(), Some(1), start + spacing)
                .is_some()
        );
    }

    /// A link that refuses, as the SDK does, once it holds more records than
    /// the cap, and that counts the Acceptances it appends.
    struct CappedLink {
        records: StdMutex<usize>,
        calls: StdMutex<usize>,
    }

    #[async_trait]
    impl AllowanceLink for CappedLink {
        async fn link_records(&self, _reader: &PubkyPublicKey) -> paykit_sdk::Result<usize> {
            Ok(*self.records.lock().unwrap())
        }

        async fn accept_pending(
            &self,
            _reader: &PubkyPublicKey,
            limit: usize,
        ) -> paykit_sdk::Result<LinkAcceptance> {
            *self.calls.lock().unwrap() += 1;
            let mut records = self.records.lock().unwrap();
            if *records > MAX_PENDING_ALLOWANCE_LINK_RECORDS {
                return Ok(LinkAcceptance {
                    accepted: 0,
                    more_pending: false,
                });
            }
            // Far more proposals are pending than any read accepts; each
            // Acceptance comes back with its Delivery Confirmation.
            *records += limit * RECORDS_PER_ACCEPTANCE;
            Ok(LinkAcceptance {
                accepted: limit,
                more_pending: true,
            })
        }
    }

    #[tokio::test]
    async fn intake_never_takes_a_link_past_the_record_cap() {
        let lock = Arc::new(TokioMutex::new(()));
        let link = CappedLink {
            records: StdMutex::new(MAX_PENDING_ALLOWANCE_LINK_RECORDS - 3),
            calls: StdMutex::new(0),
        };

        // Headroom for one Acceptance and its confirmation; more stay pending.
        let limit = acceptance_limit(*link.records.lock().unwrap());
        let first = accept_proposals(&link, &lock, &reader(), limit, LOCK_WAIT).await;
        assert_eq!(first.accepted, 1);
        assert!(!first.result.unwrap());

        // One record left: no SDK call, so the server's own Acceptances never cross it.
        let limit = acceptance_limit(*link.records.lock().unwrap());
        let second = accept_proposals(&link, &lock, &reader(), limit, LOCK_WAIT).await;
        assert_eq!(second.accepted, 0);
        assert!(second.result.unwrap());
        assert_eq!(
            *link.records.lock().unwrap(),
            MAX_PENDING_ALLOWANCE_LINK_RECORDS - 1
        );
        assert_eq!(*link.calls.lock().unwrap(), 1);

        assert_eq!(acceptance_limit(0), MAX_ALLOWANCE_ACCEPTANCES_PER_READ);
        assert_eq!(acceptance_limit(MAX_PENDING_ALLOWANCE_LINK_RECORDS + 1), 0);
    }

    #[tokio::test]
    async fn headroom_is_counted_again_after_waiting_for_the_creator_lock() {
        let lock = Arc::new(TokioMutex::new(()));
        let link = Arc::new(CappedLink {
            records: StdMutex::new(MAX_PENDING_ALLOWANCE_LINK_RECORDS - 3),
            calls: StdMutex::new(0),
        });
        // The pass counted headroom for one Acceptance.
        let limit = acceptance_limit(*link.records.lock().unwrap());
        assert_eq!(limit, 1);

        // Another Creator mutation holds the lock and uses that headroom.
        let held = lock.clone().lock_owned().await;
        let read = tokio::spawn({
            let (link, lock) = (link.clone(), lock.clone());
            async move { accept_proposals(link.as_ref(), &lock, &reader(), limit, LOCK_WAIT).await }
        });
        *link.records.lock().unwrap() += 2;
        drop(held);
        let read = read.await.unwrap();

        assert_eq!(read.accepted, 0);
        assert_eq!(*link.calls.lock().unwrap(), 0);
        assert!(*link.records.lock().unwrap() <= MAX_PENDING_ALLOWANCE_LINK_RECORDS);
    }

    #[test]
    fn a_link_over_the_record_cap_is_read_and_left_alone() {
        assert_eq!(
            link_acceptance(PendingAllowanceAcceptance::LinkHistoryTooLarge { record_cap: 16_384 })
                .unwrap(),
            LinkAcceptance {
                accepted: 0,
                more_pending: false,
            }
        );
        assert_eq!(
            link_acceptance(PendingAllowanceAcceptance::Accepted {
                records: Vec::new(),
                more_pending: true,
            })
            .unwrap(),
            LinkAcceptance {
                accepted: 0,
                more_pending: true,
            }
        );
    }
}
