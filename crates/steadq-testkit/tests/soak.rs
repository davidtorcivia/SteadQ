// Recovery soak: drives one real queue through simulated days of mixed
// traffic with pinned realtime and boottime clocks, runs default-budget
// recovery passes, and checks the queue against the logical Oracle.
//
// The long variant is sized to cross the thresholds that only show at
// scale: a ready shard larger than one pass's scan budget (327,681 entries)
// and more than 65,536 delayed buckets created over the run.
//
//   cargo test --release -p steadq-testkit --test soak -- --ignored --nocapture
//
// STEADQ_SOAK_STEPS resizes the long run and STEADQ_SOAK_SEED reseeds both.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::Path;
use std::time::Instant;

use steadq_core::{
    AckOutcome, CreateOptions, DeadReason, EnqueueInput, EnqueueOutcome, InitialState, LeaseInfo,
    LeaseOutcome, OpenOptions, Queue, RecoveryScanBudget, TransitionOutcome, WorkBudget,
};
use steadq_fs_linux::fault;
use steadq_testkit::{Oracle, OracleState, Rng};

const SEC: u64 = 1_000_000_000;
/// Corrupt receipts are reported as they are quarantined.
const EXPECTED_RECOVERY_ERRORS: [&str; 2] = ["receipt_compact_invalid", "receipt_delete_invalid"];
const PHASES: [&str; 5] = [
    "reap_leases",
    "promote_delayed",
    "cleanup_temp",
    "compact_receipts",
    "delete_receipts",
];
/// Every recovery phase must complete within this many passes.
const PHASE_PASSES: u64 = 64;
const RETENTION_NS: u64 = 3600 * SEC;
const IMMEDIATE_PER_STEP: u64 = 9;
const DELAYED_PER_STEP: u64 = 3;
const LEASES_PER_STEP: u64 = 2;
const RECOVER_EVERY: u64 = 4;
const WALK_EVERY_PASSES: u64 = 512;
const CORRUPT_EVERY: u64 = 97;
const SCAN_BUDGET_ENTRIES: usize = 65_536 * 5 + 1;
const DIRECTORY_LIMIT: usize = 65_536;
const LONG_STEPS: u64 = 44_000;
/// Whole recovery cycles the settle may take beyond its operation count.
const SETTLE_CYCLES: u64 = 4;

#[derive(Default)]
struct Side {
    /// not_before of every job that has ever been delayed, by job.
    not_before: HashMap<[u8; 16], u64>,
    /// Leases dropped without a transition, as a crashed consumer would.
    abandoned: HashSet<[u8; 16]>,
    ack_wall: HashMap<[u8; 16], u64>,
    corrupted: HashSet<[u8; 16]>,
    delayed_buckets: HashSet<u64>,
}

struct Soak {
    root: std::path::PathBuf,
    queue: Queue,
    oracle: Oracle,
    side: Side,
    rng: Rng,
    seed: u64,
    step: u64,
    pass: u64,
    realtime: u64,
    max_realtime: u64,
    boottime: u64,
    phase_done: [u64; 5],
    max_phase_gap: u64,
    floors: VecDeque<u64>,
    boottimes: VecDeque<u64>,
    max_ready: usize,
    max_delayed_dirs: usize,
    recovery_errors: BTreeMap<String, u64>,
    started: Instant,
}

#[derive(Default)]
struct Walk {
    state: HashMap<[u8; 16], &'static str>,
    ready: usize,
    leases: usize,
    delayed_dirs: usize,
    dead_buckets: usize,
    receipt_buckets: usize,
    quarantined: usize,
    /// Oldest boottime deadline of any leased file.
    oldest_lease_deadline: Option<u64>,
}

impl Soak {
    fn new(root: &Path, seed: u64) -> Self {
        let realtime = 1_800_000_000 * SEC;
        let boottime = 1_000 * SEC;
        set_clocks(realtime, boottime);
        Queue::init(
            root,
            &CreateOptions {
                shard_count: 1,
                delayed_bucket_width_ns: SEC,
                ..Default::default()
            },
        )
        .expect("init queue");
        let queue = Queue::open(
            root,
            &OpenOptions {
                allow_unsupported_fs: true,
                receipt_retention_ns: RETENTION_NS,
                ..Default::default()
            },
        )
        .expect("open queue");
        Soak {
            root: root.to_path_buf(),
            queue,
            oracle: Oracle::new(),
            side: Side::default(),
            rng: Rng::new(seed),
            seed,
            step: 0,
            pass: 0,
            realtime,
            max_realtime: realtime,
            boottime,
            phase_done: [0; 5],
            max_phase_gap: 0,
            floors: VecDeque::new(),
            boottimes: VecDeque::new(),
            max_ready: 0,
            max_delayed_dirs: 0,
            recovery_errors: BTreeMap::new(),
            started: Instant::now(),
        }
    }

    fn at(&self) -> String {
        format!("seed {} step {} pass {}", self.seed, self.step, self.pass)
    }

    fn floor(&self) -> u64 {
        self.queue
            .effective_wall_floor_ns_checked()
            .expect("wall floor")
    }

    fn advance_clock(&mut self) {
        let dt = (1 + self.rng.next_range(4)) * SEC;
        self.boottime += dt;
        self.realtime += dt;
        // Occasional rollback; the watermark must keep delayed jobs waiting.
        if self.rng.next_range(40) == 0 {
            self.realtime -= (1 + self.rng.next_range(30)) * SEC;
        }
        self.max_realtime = self.max_realtime.max(self.realtime);
        set_clocks(self.realtime, self.boottime);
    }

    fn enqueue(&mut self, not_before: Option<u64>) {
        let max_attempts = 1 + self.rng.next_range(3) as u32;
        let payload = vec![self.rng.next_u64() as u8; 16 + self.rng.next_range(48) as usize];
        let ticket = match self.queue.enqueue(EnqueueInput {
            maximum_attempts: max_attempts,
            content_type: "application/octet-stream".into(),
            payload,
            initial_not_before: not_before,
            ..Default::default()
        }) {
            EnqueueOutcome::Committed(ticket) => ticket,
            other => panic!("{}: enqueue failed: {other:?}", self.at()),
        };
        let id = ticket.job_id;
        self.oracle.record_enqueue(id, max_attempts);
        self.oracle.record_file_sync(&id);
        self.oracle.record_dest_sync(&id);
        let delayed = ticket.expected_initial_state == InitialState::Delayed;
        self.oracle.record_publish(&id, !delayed);
        if delayed {
            let nb = not_before.expect("delayed enqueue has a not_before");
            self.side.not_before.insert(id, nb);
            self.side.delayed_buckets.insert(nb.div_ceil(SEC));
        }
    }

    fn lease(&mut self) -> Option<LeaseInfo> {
        let duration = (1 + self.rng.next_range(5)) * SEC;
        let info = match self.queue.lease(0, duration) {
            LeaseOutcome::Leased(info) => info,
            LeaseOutcome::Empty => return None,
            other => panic!("{}: lease failed: {other:?}", self.at()),
        };
        let id = info.job_id;
        let at = self.at();
        assert!(
            !self.side.corrupted.contains(&id),
            "{at}: corrupt job {} was delivered",
            hex(&id)
        );
        let job = self
            .oracle
            .get(&id)
            .unwrap_or_else(|| panic!("{at}: leased unknown job {}", hex(&id)))
            .clone();
        // Generations the queue must have spent between our last observation
        // and this claim.
        let hidden_transitions = match job.state {
            OracleState::Ready => 0,
            OracleState::Delayed => {
                let nb = self.side.not_before[&id];
                assert!(
                    nb <= self.max_realtime,
                    "{at}: delayed job {} delivered at wall {} before not_before {nb}",
                    hex(&id),
                    self.max_realtime
                );
                1
            }
            OracleState::Leased if self.side.abandoned.remove(&id) => 1,
            state => panic!(
                "{at}: job {} delivered again from oracle state {state:?}",
                hex(&id)
            ),
        };
        assert_eq!(
            (info.generation, info.attempt),
            (job.generation + hidden_transitions + 1, job.attempt + 1),
            "{at}: job {} generation/attempt diverged from the oracle",
            hex(&id)
        );
        let entry = self.oracle.get_mut(&id).expect("known job");
        entry.state = OracleState::Ready;
        entry.generation += hidden_transitions;
        self.oracle.record_claim(&id, info.token);
        assert!(self.oracle.check_i9(), "{at}: attempts exceeded maximum");
        Some(info)
    }

    fn settle_lease(&mut self, info: LeaseInfo, corrupt_receipt: bool) {
        let id = info.job_id;
        let at = self.at();
        match self.rng.next_range(20) {
            0..=9 => {
                let floor = self.floor();
                match self.queue.ack(&info) {
                    AckOutcome::Acked => {}
                    other => panic!("{at}: ack failed: {other:?}"),
                }
                self.oracle.record_ack(&id);
                self.side.ack_wall.insert(id, floor);
                if corrupt_receipt {
                    self.corrupt_receipt(&info, floor);
                }
            }
            10..=12 => {
                committed(&at, "retry_now", self.queue.retry_now(&info));
                if info.attempt >= info.maximum_attempts {
                    self.oracle.record_bury(&id);
                } else {
                    self.oracle.record_retry(&id);
                }
            }
            13..=14 => {
                let nb = self.floor() + (1 + self.rng.next_range(300)) * SEC;
                committed(&at, "retry_at", self.queue.retry_at(&info, nb));
                if info.attempt >= info.maximum_attempts {
                    self.oracle.record_bury(&id);
                } else {
                    self.oracle.record_retry(&id);
                    self.oracle.get_mut(&id).expect("known job").state = OracleState::Delayed;
                    self.side.not_before.insert(id, nb);
                    self.side.delayed_buckets.insert(nb.div_ceil(SEC));
                }
            }
            15 => {
                committed(
                    &at,
                    "bury",
                    self.queue.bury(&info, DeadReason::AdministrativeBury),
                );
                self.oracle.record_bury(&id);
            }
            _ => {
                self.side.abandoned.insert(id);
            }
        }
    }

    fn corrupt_receipt(&mut self, info: &LeaseInfo, floor: u64) {
        let format = self.queue.format();
        let bucket = floor / format.terminal_bucket_width_ns();
        let common = steadq_names::CommonFields {
            job_id: info.job_id,
            generation: info.generation + 1,
            attempt: info.attempt,
            maximum_attempts: info.maximum_attempts,
        };
        let bucket_hex = steadq_names::bucket_hex(bucket);
        let shard_hex = steadq_names::shard_hex(0);
        let name = steadq_names::make_receipt_name(
            format.queue_id(),
            &bucket_hex,
            &shard_hex,
            &common,
            &info.token,
        );
        corrupt_file(
            &self
                .root
                .join(format!("receipts/{bucket_hex}/{shard_hex}/{name}")),
        );
        self.oracle.get_mut(&info.job_id).expect("known job").state = OracleState::Quarantine;
        self.side.corrupted.insert(info.job_id);
    }

    /// Corrupt the first ready entry in directory order, so the next lease
    /// reaches it and must move it aside instead of stalling on it.
    fn corrupt_first_ready(&mut self) {
        let dir = self.root.join("ready").join(steadq_names::shard_hex(0));
        let Some((id, path)) = std::fs::read_dir(&dir)
            .expect("read ready shard")
            .map(|entry| entry.expect("ready entry"))
            .find_map(|entry| {
                let name = entry.file_name().into_string().ok()?;
                let parsed = steadq_names::parse_ready(&name).ok()?;
                Some((parsed.common.job_id, entry.path()))
            })
        else {
            return;
        };
        corrupt_file(&path);
        self.oracle.get_mut(&id).expect("known job").state = OracleState::Quarantine;
        self.side.corrupted.insert(id);
        if let Some(info) = self.lease() {
            assert!(
                !path.exists(),
                "{}: lease returned {} and left corrupt {} in ready",
                self.at(),
                hex(&info.job_id),
                path.display()
            );
            self.settle_lease(info, false);
        }
    }

    fn recover(&mut self) {
        self.pass += 1;
        let before = self.cursor();
        let report = self
            .queue
            .recover_with_scan_budget(&WorkBudget::default(), &RecoveryScanBudget::default());
        let stats = &report.stats;
        for error in &stats.errors {
            assert!(
                EXPECTED_RECOVERY_ERRORS.contains(&error.operation.as_str()),
                "{}: unexpected recovery error {error:?}",
                self.at()
            );
            *self
                .recovery_errors
                .entry(error.operation.clone())
                .or_default() += 1;
        }
        let after = self.cursor();
        let at = self.at();

        // Phases completed this pass: the cyclic range [before, after), or
        // the whole cycle when a pass ends where it started with budget left.
        let from = phase_index(&before);
        let to = phase_index(&after);
        let completed = if from == to && !stats.budget_exhausted {
            5
        } else {
            (to + 5 - from) % 5
        };
        for offset in 0..completed {
            self.phase_done[(from + offset) % 5] = self.pass;
        }
        for (phase, done) in PHASES.iter().zip(self.phase_done) {
            let gap = self.pass - done;
            self.max_phase_gap = self.max_phase_gap.max(gap);
            assert!(
                gap <= PHASE_PASSES,
                "{at}: recovery phase {phase} has not completed in {gap} passes; cursor {after}"
            );
        }

        let mutations = stats.operations_attempted
            + stats.delayed_promoted
            + stats.leases_reaped
            + stats.buckets_removed
            + stats.quarantined.len() as u32;
        assert!(
            !(stats.budget_exhausted && mutations == 0 && before == after),
            "{at}: recovery cursor repeated without progress: {after}; scan {:?}",
            report.scan
        );

        let floor = self.floor();
        self.floors.push_back(floor);
        self.boottimes.push_back(self.boottime);
        if self.floors.len() as u64 > 2 * PHASE_PASSES {
            self.floors.pop_front();
            self.boottimes.pop_front();
        }
        // A bucket older than every floor seen over two full phase windows
        // has been through a complete promotion pass and must be gone.
        let stale_before = self.floors.iter().min().copied().unwrap_or(floor) / SEC;
        let delayed = std::fs::read_dir(self.root.join("delayed"))
            .expect("read delayed")
            .map(|entry| entry.expect("delayed entry").file_name())
            .collect::<Vec<_>>();
        self.max_delayed_dirs = self.max_delayed_dirs.max(delayed.len());
        if self.floors.len() as u64 == 2 * PHASE_PASSES {
            for name in &delayed {
                let bucket = steadq_names::bucket_from_hex(name.to_str().expect("ascii bucket"))
                    .expect("canonical bucket");
                assert!(
                    bucket + 1 >= stale_before,
                    "{at}: drained delayed bucket {bucket} still present below wall bucket \
                     {stale_before}; delayed/ holds {} entries",
                    delayed.len()
                );
            }
        }

        if self.pass.is_multiple_of(WALK_EVERY_PASSES) {
            self.verify(false);
        }
    }

    fn cursor(&self) -> serde_json::Value {
        match std::fs::read(self.root.join("control/recovery-cursor.json")) {
            Ok(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes).expect("cursor json")
                ["cursor"]
                .clone(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                serde_json::json!({ "phase": "reap_leases" })
            }
            Err(error) => panic!("read recovery cursor: {error}"),
        }
    }

    /// Compare every job on disk with the oracle. `settled` means clocks
    /// have jumped past every deadline and recovery has gone quiet.
    fn verify(&mut self, settled: bool) {
        let at = self.at();
        let walk = walk(&self.root, &at);
        self.max_ready = self.max_ready.max(walk.ready);
        let floor = self.floor();
        if let (Some(deadline), Some(oldest)) = (walk.oldest_lease_deadline, self.boottimes.front())
        {
            assert!(
                deadline >= *oldest || self.boottimes.len() < 2 * PHASE_PASSES as usize,
                "{at}: lease expired at boottime {deadline} still unreaped at {}",
                self.boottime
            );
        }
        for job in self.oracle.jobs() {
            let id = hex(&job.job_id);
            let found = walk.state.get(&job.job_id).copied();
            let ok = match job.state {
                OracleState::Ready => found == Some("ready"),
                OracleState::Delayed if settled => found == Some("ready"),
                OracleState::Delayed => matches!(found, Some("delayed" | "ready")),
                OracleState::Leased if settled => matches!(found, Some("ready" | "dead")),
                OracleState::Leased => matches!(found, Some("leased" | "ready" | "dead")),
                OracleState::Dead => found == Some("dead"),
                OracleState::Receipt if settled => found.is_none(),
                OracleState::Receipt => {
                    found == Some("receipt")
                        || (found.is_none()
                            && self.side.ack_wall[&job.job_id] + RETENTION_NS <= floor)
                }
                OracleState::Quarantine => found.is_none() || !settled && found == Some("receipt"),
                OracleState::Hidden => found.is_none(),
            };
            assert!(
                ok,
                "{at}: job {id} is {found:?} on disk but {:?} in the oracle",
                job.state
            );
        }
        assert_eq!(
            walk.state.len(),
            walk.state
                .keys()
                .filter(|id| self.oracle.get(id).is_some())
                .count(),
            "{at}: unknown jobs on disk"
        );
        if settled {
            assert_eq!(
                walk.delayed_dirs, 0,
                "{at}: delayed/ not empty after settle"
            );
            assert_eq!(
                walk.quarantined,
                self.side.corrupted.len(),
                "{at}: quarantine does not hold every corrupted object"
            );
        }
        eprintln!(
            "soak {at}: jobs {} ready {} delayed-dirs {} leases {} dead-buckets {} \
             receipt-buckets {} quarantined {} after {:?}",
            walk.state.len(),
            walk.ready,
            walk.delayed_dirs,
            walk.leases,
            walk.dead_buckets,
            walk.receipt_buckets,
            walk.quarantined,
            self.started.elapsed()
        );
    }

    fn step(&mut self) {
        self.step += 1;
        self.advance_clock();
        for _ in 0..IMMEDIATE_PER_STEP {
            self.enqueue(None);
        }
        for _ in 0..DELAYED_PER_STEP {
            let nb = self.floor() + (1 + self.rng.next_range(600)) * SEC;
            self.enqueue(Some(nb));
        }
        for index in 0..LEASES_PER_STEP {
            if let Some(info) = self.lease() {
                let corrupt = index == 0 && self.step.is_multiple_of(CORRUPT_EVERY);
                self.settle_lease(info, corrupt);
            }
        }
        if self.step.is_multiple_of(CORRUPT_EVERY) {
            self.corrupt_first_ready();
        }
        if self.step.is_multiple_of(RECOVER_EVERY) {
            self.recover();
        }
    }

    /// Delayed jobs and bucket directories, leases, and receipts on disk.
    fn pending(&self) -> usize {
        let walk = walk(&self.root, &self.at());
        let delayed = walk
            .state
            .values()
            .filter(|state| **state == "delayed")
            .count();
        delayed + walk.delayed_dirs + walk.leases + count_files(&self.root.join("receipts"))
    }

    /// Jump both clocks past every deadline and retention window, then run
    /// recovery until no delayed job, lease, or receipt is left.
    fn settle(&mut self) {
        self.realtime = self.max_realtime + 2 * RETENTION_NS;
        self.max_realtime = self.realtime;
        self.boottime += 2 * RETENTION_NS;
        set_clocks(self.realtime, self.boottime);
        // Each pending job, receipt, or delayed directory costs at most two
        // operations, a pass with work left spends its whole operation
        // budget, and every phase completes within PHASE_PASSES, so the
        // queue drains within this many passes.
        let pending = self.pending();
        let operations = u64::from(WorkBudget::default().max_operations);
        let passes = (2 * pending as u64).div_ceil(operations) + SETTLE_CYCLES * PHASE_PASSES;
        let limit = self.pass + passes;
        loop {
            for _ in 0..8 {
                self.recover();
            }
            let left = self.pending();
            if left == 0 {
                break;
            }
            assert!(
                self.pass < limit,
                "{}: {left} of {pending} delayed jobs and buckets, leases, and receipts \
                 remain after {passes} settle passes",
                self.at()
            );
        }
        self.verify(true);
    }
}

fn set_clocks(realtime: u64, boottime: u64) {
    fault::set_clock_realtime_ns(realtime);
    fault::set_clock_boottime_ns(boottime);
    assert_eq!(steadq_fs_linux::clock_realtime_ns().unwrap(), realtime);
    assert_eq!(steadq_fs_linux::clock_boottime_ns().unwrap(), boottime);
}

fn committed(at: &str, operation: &str, outcome: TransitionOutcome) {
    assert!(
        matches!(outcome, TransitionOutcome::Committed),
        "{at}: {operation} failed: {outcome:?}"
    );
}

fn phase_index(cursor: &serde_json::Value) -> usize {
    let phase = cursor["phase"].as_str().expect("cursor phase");
    PHASES
        .iter()
        .position(|candidate| *candidate == phase)
        .unwrap_or_else(|| panic!("unknown recovery phase {phase}"))
}

fn corrupt_file(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|error| panic!("corrupt {}: {error}", path.display()));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("open for corruption");
    std::os::unix::fs::FileExt::write_all_at(&file, &[0xA5; 8], 0).expect("corrupt header");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn names(path: &Path) -> Vec<String> {
    match std::fs::read_dir(path) {
        Ok(entries) => entries
            .map(|entry| {
                entry
                    .expect("dir entry")
                    .file_name()
                    .into_string()
                    .expect("utf8 name")
            })
            .collect(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => panic!("read {}: {error}", path.display()),
    }
}

/// Job id and one state-specific field parsed from a filename.
type ParseName = fn(&str) -> Option<([u8; 16], u64)>;

/// Record every job file under `dir` (at `depth` directory levels below it)
/// as `state`, failing on a job that appears twice.
fn collect(
    walk: &mut Walk,
    dir: &Path,
    depth: usize,
    state: &'static str,
    at: &str,
    parse: ParseName,
) {
    for name in names(dir) {
        let path = dir.join(&name);
        if depth > 0 {
            collect(walk, &path, depth - 1, state, at, parse);
            continue;
        }
        let Some((id, extra)) = parse(&name) else {
            continue;
        };
        if state == "leased" {
            walk.leases += 1;
            walk.oldest_lease_deadline =
                Some(walk.oldest_lease_deadline.map_or(extra, |d| d.min(extra)));
        }
        if state == "ready" {
            walk.ready += 1;
        }
        if let Some(previous) = walk.state.insert(id, state) {
            panic!("{at}: job {} is both {previous} and {state}", hex(&id));
        }
    }
}

fn walk(root: &Path, at: &str) -> Walk {
    let mut walk = Walk::default();
    collect(&mut walk, &root.join("ready"), 1, "ready", at, |name| {
        steadq_names::parse_ready(name)
            .ok()
            .map(|p| (p.common.job_id, 0))
    });
    collect(&mut walk, &root.join("delayed"), 2, "delayed", at, |name| {
        steadq_names::parse_delayed(name)
            .ok()
            .map(|p| (p.common.job_id, p.not_before_ns))
    });
    // Claims rename a job to its lease name inside its ready shard.
    collect(&mut walk, &root.join("ready"), 1, "leased", at, |name| {
        steadq_names::parse_leased(name)
            .ok()
            .map(|p| (p.common.job_id, p.boottime_deadline_ns))
    });
    collect(&mut walk, &root.join("dead"), 2, "dead", at, |name| {
        steadq_names::parse_dead(name)
            .ok()
            .map(|p| (p.common.job_id, 0))
    });
    collect(
        &mut walk,
        &root.join("receipts"),
        2,
        "receipt",
        at,
        |name| {
            steadq_names::parse_receipt(name)
                .ok()
                .map(|p| (p.common.job_id, 0))
        },
    );
    walk.delayed_dirs = names(&root.join("delayed")).len();
    walk.dead_buckets = names(&root.join("dead")).len();
    walk.receipt_buckets = names(&root.join("receipts")).len();
    walk.quarantined = count_files(&root.join("quarantine"));
    walk
}

fn count_files(dir: &Path) -> usize {
    names(dir)
        .iter()
        .map(|name| {
            let path = dir.join(name);
            if path.is_dir() {
                count_files(&path)
            } else {
                1
            }
        })
        .sum()
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .map(|value| {
            value
                .parse()
                .unwrap_or_else(|_| panic!("{name} must be a number"))
        })
        .unwrap_or(default)
}

fn run(steps: u64) -> (usize, usize) {
    let seed = env_u64("STEADQ_SOAK_SEED", 1);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut soak = Soak::new(dir.path(), seed);
    for _ in 0..steps {
        soak.step();
    }
    soak.settle();
    eprintln!(
        "soak seed {seed}: {steps} steps, {} passes, {} jobs, max ready {}, delayed buckets \
         created {}, max delayed/ entries {}, max phase gap {} passes, simulated {} s, {:?}; \
         recovery errors {:?}",
        soak.pass,
        soak.oracle.jobs().count(),
        soak.max_ready,
        soak.side.delayed_buckets.len(),
        soak.max_delayed_dirs,
        soak.max_phase_gap,
        (soak.max_realtime - 1_800_000_000 * SEC) / SEC,
        soak.started.elapsed(),
        soak.recovery_errors
    );
    (soak.max_ready, soak.side.delayed_buckets.len())
}

#[test]
fn soak_short() {
    run(env_u64("STEADQ_SOAK_SHORT_STEPS", 100));
}

#[test]
#[ignore = "long soak; run with --ignored, sized by STEADQ_SOAK_STEPS"]
fn soak_long() {
    let steps = env_u64("STEADQ_SOAK_STEPS", LONG_STEPS);
    let (max_ready, delayed_buckets) = run(steps);
    if steps >= LONG_STEPS {
        assert!(
            max_ready > SCAN_BUDGET_ENTRIES,
            "ready backlog {max_ready} never exceeded one pass's scan budget"
        );
        assert!(
            delayed_buckets > DIRECTORY_LIMIT,
            "only {delayed_buckets} delayed buckets created"
        );
    }
}
