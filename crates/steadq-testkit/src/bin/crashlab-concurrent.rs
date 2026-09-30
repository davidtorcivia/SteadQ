// Crash-lab concurrent workload for the dm-flakey power-cut lane.
//
// Several threads, each with its own queue handle, run a random mix of
// strict enqueue, lease, ack, retry, bury, recovery, deferred enqueue with
// sync, and group-commit batches until killed. Every returned outcome is
// appended as one JSONL line to an op log that lives OFF the tested device,
// so post-cut lines survive; the runner appends a cut marker to the same file
// before it drops writes. A line before the marker is an operation that
// returned before the cut.
//
// Results: committed (durable enqueue), deferred (published, not yet
// synced), not_committed, unknown, leased, empty, acked, retried, buried,
// lease_lost, error. Deferred and batched enqueues are logged committed only
// after their sync or commit returns; batched acks likewise.
//
// Usage: crashlab-concurrent --queue DIR --oplog FILE [--workers N] [--seed N]

use std::io::Write as _;
use std::sync::{Arc, Mutex};
use steadq_core::{
    AckOutcome, BatchAckOutcome, BatchEnqueueOutcome, BatchLeaseOutcome, CreateOptions, DeadReason,
    EnqueueInput, EnqueueOutcome, LeaseInfo, LeaseOutcome, OpenOptions, Queue, TransitionOutcome,
    WorkBudget,
};

const SHORT_LEASE_NS: u64 = 1_000_000_000;
const LONG_LEASE_NS: u64 = 30_000_000_000;

/// xorshift64*: deterministic, dependency-free.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct Log(Arc<Mutex<std::fs::File>>, usize);

impl Log {
    fn line(&self, op: &str, job: Option<&[u8; 16]>, result: &str) {
        let job = job.map(|j| hex(j)).unwrap_or_default();
        let text = format!(
            "{{\"w\":{},\"op\":\"{op}\",\"job\":\"{job}\",\"result\":\"{result}\"}}\n",
            self.1
        );
        // One write per line on an O_APPEND file keeps lines whole.
        let _ = self.0.lock().unwrap().write_all(text.as_bytes());
    }
}

fn payload(rng: &mut Rng) -> Vec<u8> {
    let len = match rng.next() % 16 {
        0 => 128 * 1024,
        1 => 0,
        _ => (rng.next() % 8192) as usize,
    };
    (0..len).map(|_| rng.next() as u8).collect()
}

fn input(rng: &mut Rng) -> EnqueueInput {
    EnqueueInput {
        maximum_attempts: 2 + (rng.next() % 3) as u32,
        content_type: "application/octet-stream".into(),
        payload: payload(rng),
        ..Default::default()
    }
}

fn open(queue: &str, deferred: bool) -> Queue {
    Queue::open(
        std::path::Path::new(queue),
        &OpenOptions {
            allow_unsupported_fs: true,
            deferred_dir_sync: deferred,
            ..Default::default()
        },
    )
    .unwrap_or_else(|e| {
        eprintln!("crashlab-concurrent: open failed: {e}");
        std::process::exit(2);
    })
}

fn enqueue_result(outcome: &EnqueueOutcome) -> (&[u8; 16], &'static str) {
    match outcome {
        EnqueueOutcome::Committed(t) => (&t.job_id, "committed"),
        EnqueueOutcome::Deferred(t) => (&t.job_id, "deferred"),
        EnqueueOutcome::NotCommitted(t, _) => (&t.job_id, "not_committed"),
        EnqueueOutcome::OutcomeUnknown(t, _) => (&t.job_id, "unknown"),
    }
}

fn transition_result(outcome: &TransitionOutcome, ok: &'static str) -> &'static str {
    match outcome {
        TransitionOutcome::Committed => ok,
        TransitionOutcome::LeaseLost => "lease_lost",
        TransitionOutcome::NotCommitted(_) => "not_committed",
        TransitionOutcome::OutcomeUnknown(_) => "unknown",
    }
}

/// Strict single-operation worker; `deferred` switches enqueue to deferred
/// directory sync with an explicit `sync()` every few enqueues.
fn strict_worker(queue_dir: &str, log: Log, seed: u64, deferred: bool) {
    let mut queue = open(queue_dir, deferred);
    let mut rng = Rng(seed | 1);
    let mut leases: Vec<LeaseInfo> = Vec::new();
    let mut unsynced: Vec<[u8; 16]> = Vec::new();
    loop {
        let pick = rng.next() % 100;
        if pick < 35 {
            let outcome = queue.enqueue(input(&mut rng));
            let (job, result) = enqueue_result(&outcome);
            log.line("enqueue", Some(job), result);
            if matches!(outcome, EnqueueOutcome::Deferred(_)) {
                unsynced.push(*job);
            }
        } else if pick < 42 && deferred {
            match queue.sync() {
                Ok(()) => {
                    for job in unsynced.drain(..) {
                        log.line("enqueue", Some(&job), "committed");
                    }
                    log.line("sync", None, "ok");
                }
                Err(_) => {
                    unsynced.clear();
                    log.line("sync", None, "error");
                }
            }
        } else if pick < 62 && leases.len() < 4 {
            let duration = if rng.next().is_multiple_of(4) {
                SHORT_LEASE_NS
            } else {
                LONG_LEASE_NS
            };
            match queue.lease(0, duration) {
                LeaseOutcome::Leased(lease) => {
                    log.line("lease", Some(&lease.job_id), "leased");
                    leases.push(lease);
                }
                LeaseOutcome::Empty => log.line("lease", None, "empty"),
                LeaseOutcome::NotCommitted(_) => log.line("lease", None, "not_committed"),
                LeaseOutcome::OutcomeUnknown(_) => log.line("lease", None, "unknown"),
            }
        } else if pick < 92 && !leases.is_empty() {
            let lease = leases.remove((rng.next() % leases.len() as u64) as usize);
            let which = rng.next() % 10;
            if which < 6 {
                let result = match queue.ack(&lease) {
                    AckOutcome::Acked => "acked",
                    AckOutcome::AlreadyAcked => "already_acked",
                    AckOutcome::LeaseLost => "lease_lost",
                    AckOutcome::NotCommitted(_) => "not_committed",
                    AckOutcome::OutcomeUnknown(_) => "unknown",
                };
                log.line("ack", Some(&lease.job_id), result);
            } else if which < 9 {
                let outcome = queue.retry_now(&lease);
                log.line(
                    "retry",
                    Some(&lease.job_id),
                    transition_result(&outcome, "retried"),
                );
            } else {
                let outcome = queue.bury(&lease, DeadReason::AdministrativeBury);
                log.line(
                    "bury",
                    Some(&lease.job_id),
                    transition_result(&outcome, "buried"),
                );
            }
        } else if pick >= 97 {
            let stats = queue.recover(&WorkBudget {
                max_operations: 1_000,
                max_duration_ms: 200,
            });
            let result = if stats.errors.is_empty() {
                "ok"
            } else {
                "error"
            };
            log.line("recover", None, result);
        }
    }
}

/// Group-commit worker: a batch of enqueues, then a batch of lease+ack,
/// each made durable by one `commit()`.
fn batch_worker(queue_dir: &str, log: Log, seed: u64) {
    let mut queue = open(queue_dir, false);
    let mut rng = Rng(seed | 1);
    loop {
        let size = 1 + (rng.next() % 16) as usize;
        let mut batch = queue.batch();
        for _ in 0..size {
            match batch.enqueue(input(&mut rng)) {
                BatchEnqueueOutcome::Pending(_) => {}
                BatchEnqueueOutcome::NotCommitted(t, _) => {
                    log.line("enqueue", Some(&t.job_id), "not_committed")
                }
                BatchEnqueueOutcome::OutcomeUnknown(t, _) => {
                    log.line("enqueue", Some(&t.job_id), "unknown")
                }
            }
        }
        let (Ok(outcome) | Err(outcome)) = batch.commit();
        for t in &outcome.committed_enqueues {
            log.line("enqueue", Some(&t.job_id), "committed");
        }
        for (t, _) in &outcome.outcome_unknown_enqueues {
            log.line("enqueue", Some(&t.job_id), "unknown");
        }

        let mut batch = queue.batch();
        let mut acked = Vec::new();
        for _ in 0..size {
            let lease = match batch.lease(0, LONG_LEASE_NS) {
                BatchLeaseOutcome::Pending(lease) => lease,
                _ => break,
            };
            if let BatchAckOutcome::Pending = batch.ack(&lease) {
                acked.push(lease.job_id);
            }
        }
        match batch.commit() {
            Ok(_) => {
                for job in &acked {
                    log.line("ack", Some(job), "acked");
                }
            }
            Err(_) => {
                for job in &acked {
                    log.line("ack", Some(job), "unknown");
                }
            }
        }
    }
}

fn main() {
    let mut queue = String::new();
    let mut oplog = String::new();
    let mut workers = 4usize;
    let mut seed = 1u64;
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let value = it.next().unwrap_or_default();
        match flag.as_str() {
            "--queue" => queue = value,
            "--oplog" => oplog = value,
            "--workers" => workers = value.parse().unwrap_or(0),
            "--seed" => seed = value.parse().unwrap_or(1),
            _ => {
                eprintln!("crashlab-concurrent: unknown flag {flag}");
                std::process::exit(2);
            }
        }
    }
    if queue.is_empty() || oplog.is_empty() || workers < 3 {
        eprintln!(
            "usage: crashlab-concurrent --queue DIR --oplog FILE [--workers N>=3] [--seed N]"
        );
        std::process::exit(2);
    }
    if let Err(e) = Queue::init(std::path::Path::new(&queue), &CreateOptions::default()) {
        eprintln!("crashlab-concurrent: init failed: {e}");
        std::process::exit(2);
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&oplog)
        .unwrap_or_else(|e| {
            eprintln!("crashlab-concurrent: cannot open oplog {oplog}: {e}");
            std::process::exit(2);
        });
    let file = Arc::new(Mutex::new(file));
    let handles: Vec<_> = (0..workers)
        .map(|w| {
            let log = Log(Arc::clone(&file), w);
            let queue = queue.clone();
            let seed = seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(w as u64);
            std::thread::spawn(move || match w {
                0 => strict_worker(&queue, log, seed, true),
                1 => batch_worker(&queue, log, seed),
                _ => strict_worker(&queue, log, seed, false),
            })
        })
        .collect();
    for h in handles {
        let _ = h.join();
    }
}
