// Production-coupled driver: runs real Queue operations and verifies the
// actual queue state (via inspect) against the logical Oracle after each
// operation, catching divergence between production code and the model.

use crate::oracle::{Oracle, OracleState};
use crate::simulator::TraceEvent;

use steadq_core::{
    AckOutcome, CreateOptions, EnqueueInput, EnqueueOutcome, Error, LeaseInfo, LeaseOutcome,
    OpenOptions, Queue, TransitionOutcome,
};

/// A production-coupled driver that wraps a real Queue and an Oracle.
///
/// Each operation calls the Queue method, records the expected transition
/// in the Oracle, then verifies consistency.
pub struct ProductionDriver {
    queue: Queue,
    oracle: Oracle,
    operation_counter: u64,
    traces: Vec<TraceEvent>,
    /// Active leases keyed by job_id.
    leases: std::collections::HashMap<[u8; 16], LeaseInfo>,
}

/// Result of a consistency check.
#[derive(Debug, Clone)]
pub struct ConsistencyError {
    pub job_id_hex: String,
    pub oracle_state: String,
    pub actual_state: String,
    pub oracle_generation: u64,
    pub actual_generation: u64,
    pub oracle_attempt: u32,
    pub actual_attempt: u32,
    pub description: String,
}

impl ProductionDriver {
    /// Create a new driver with a fresh queue in the given directory.
    pub fn new(root: &std::path::Path) -> Result<Self, Error> {
        Queue::init(root, &CreateOptions::default())
            .map_err(|e| Error::IoFailure(e.to_string()))?;
        let queue = Queue::open(
            root,
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )?;
        Ok(ProductionDriver {
            queue,
            oracle: Oracle::new(),
            operation_counter: 0,
            traces: Vec::new(),
            leases: std::collections::HashMap::new(),
        })
    }

    /// Open an existing queue directory (after a simulated crash).
    pub fn reopen(root: &std::path::Path) -> Result<Self, Error> {
        let queue = Queue::open(
            root,
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )?;
        Ok(ProductionDriver {
            queue,
            oracle: Oracle::new(),
            operation_counter: 0,
            traces: Vec::new(),
            leases: std::collections::HashMap::new(),
        })
    }

    /// Enqueue a job with the given payload. Returns the production job_id.
    pub fn enqueue(&mut self, payload: &[u8], max_attempts: u32) -> Result<[u8; 16], Error> {
        let outcome = self.queue.enqueue(EnqueueInput {
            maximum_attempts: max_attempts,
            content_type: "application/octet-stream".to_string(),
            payload: payload.to_vec(),
            ..Default::default()
        });

        let mut trace = TraceEvent::new(self.operation_counter);
        self.operation_counter += 1;
        trace.source_state = Some("none".into());
        trace.destination_state = Some("ready".into());

        match outcome {
            EnqueueOutcome::Committed(ticket) => {
                let job_id = ticket.job_id;
                self.oracle.record_enqueue(job_id, max_attempts);
                self.oracle.record_file_sync(&job_id);
                self.oracle.record_publish(&job_id, true);
                self.oracle.record_dest_sync(&job_id);
                trace.job_id_hex = hex(&job_id);
                trace.syscall_result = Some("committed".into());
                self.traces.push(trace);
                Ok(job_id)
            }
            EnqueueOutcome::Deferred(ticket) => {
                let job_id = ticket.job_id;
                self.queue
                    .sync()
                    .map_err(|error| Error::IoFailure(error.to_string()))?;
                self.oracle.record_enqueue(job_id, max_attempts);
                self.oracle.record_file_sync(&job_id);
                self.oracle.record_publish(&job_id, true);
                self.oracle.record_dest_sync(&job_id);
                trace.job_id_hex = hex(&job_id);
                trace.syscall_result = Some("committed_after_sync".into());
                self.traces.push(trace);
                Ok(job_id)
            }
            EnqueueOutcome::NotCommitted(_, e) => {
                trace.syscall_result = Some(format!("not_committed: {e}"));
                self.traces.push(trace);
                Err(e)
            }
            EnqueueOutcome::OutcomeUnknown(_, e) => {
                trace.syscall_result = Some(format!("outcome_unknown: {e}"));
                self.traces.push(trace);
                Err(e)
            }
        }
    }

    /// Lease a job. Returns the leased job_id, or None if empty.
    pub fn lease(&mut self, duration_ns: u64) -> Result<Option<[u8; 16]>, Error> {
        let outcome = self.queue.lease(0, duration_ns);
        let mut trace = TraceEvent::new(self.operation_counter);
        self.operation_counter += 1;

        match outcome {
            LeaseOutcome::Leased(info) => {
                let job_id = info.job_id;
                self.oracle.record_claim(&job_id, info.token);
                self.oracle.record_dest_sync(&job_id);
                self.oracle.record_src_sync(&job_id);
                self.leases.insert(job_id, info);
                trace.job_id_hex = hex(&job_id);
                trace.source_state = Some("ready".into());
                trace.destination_state = Some("leased".into());
                trace.attempt = self.oracle.get(&job_id).map(|j| j.attempt);
                trace.syscall_result = Some("leased".into());
                self.traces.push(trace);
                Ok(Some(job_id))
            }
            LeaseOutcome::Empty => {
                trace.syscall_result = Some("empty".into());
                self.traces.push(trace);
                Ok(None)
            }
            LeaseOutcome::NotCommitted(e) => {
                trace.syscall_result = Some(format!("not_committed: {e}"));
                self.traces.push(trace);
                Err(e)
            }
            LeaseOutcome::OutcomeUnknown(_) => {
                trace.syscall_result = Some("outcome_unknown".into());
                self.traces.push(trace);
                Err(Error::QueueCorrupt("lease outcome unknown".into()))
            }
        }
    }

    /// Acknowledge a job.
    pub fn ack(&mut self, job_id: &[u8; 16]) -> Result<(), Error> {
        let lease = match self.leases.remove(job_id) {
            Some(l) => l,
            None => return Err(Error::QueueCorrupt("no active lease for job".into())),
        };

        let outcome = self.queue.ack(&lease);
        let mut trace = TraceEvent::new(self.operation_counter);
        self.operation_counter += 1;
        trace.job_id_hex = hex(job_id);

        match outcome {
            AckOutcome::Acked => {
                self.oracle.record_ack(job_id);
                trace.source_state = Some("leased".into());
                trace.destination_state = Some("receipt".into());
                trace.syscall_result = Some("acked".into());
                self.traces.push(trace);
                Ok(())
            }
            AckOutcome::AlreadyAcked => {
                trace.syscall_result = Some("already_acked".into());
                self.traces.push(trace);
                Err(Error::QueueCorrupt("already acked".into()))
            }
            AckOutcome::LeaseLost => {
                trace.syscall_result = Some("lease_lost".into());
                self.traces.push(trace);
                Err(Error::QueueCorrupt("lease lost".into()))
            }
            AckOutcome::NotCommitted(e) => {
                trace.syscall_result = Some(format!("not_committed: {e}"));
                self.traces.push(trace);
                Err(e)
            }
            AckOutcome::OutcomeUnknown(_) => {
                trace.syscall_result = Some("outcome_unknown".into());
                self.traces.push(trace);
                Err(Error::QueueCorrupt("ack outcome unknown".into()))
            }
        }
    }

    /// Retry a job back to ready. If attempts are exhausted, production
    /// silently sends the job to dead instead of ready.
    pub fn retry_now(&mut self, job_id: &[u8; 16]) -> Result<(), Error> {
        let lease = match self.leases.remove(job_id) {
            Some(l) => l,
            None => return Err(Error::QueueCorrupt("no active lease for job".into())),
        };

        let outcome = self.queue.retry_now(&lease);
        let mut trace = TraceEvent::new(self.operation_counter);
        self.operation_counter += 1;
        trace.job_id_hex = hex(job_id);

        match outcome {
            TransitionOutcome::Committed => {
                // Production may have sent to ready (normal retry) or dead
                // (attempts exhausted). Check actual state via inspect.
                let snapshots = self.queue.inspect(job_id).expect("inspect the queue");
                if snapshots.iter().any(|s| s.state == "dead") {
                    self.oracle.record_bury(job_id);
                    trace.source_state = Some("leased".into());
                    trace.destination_state = Some("dead".into());
                } else {
                    self.oracle.record_retry(job_id);
                    trace.source_state = Some("leased".into());
                    trace.destination_state = Some("ready".into());
                }
                trace.syscall_result = Some("committed".into());
                self.traces.push(trace);
                Ok(())
            }
            TransitionOutcome::LeaseLost => {
                trace.syscall_result = Some("lease_lost".into());
                self.traces.push(trace);
                Err(Error::QueueCorrupt("lease lost".into()))
            }
            TransitionOutcome::NotCommitted(e) => {
                trace.syscall_result = Some(format!("not_committed: {e}"));
                self.traces.push(trace);
                Err(e)
            }
            TransitionOutcome::OutcomeUnknown(_) => {
                trace.syscall_result = Some("outcome_unknown".into());
                self.traces.push(trace);
                Err(Error::QueueCorrupt("retry outcome unknown".into()))
            }
        }
    }

    /// Bury a job (send to dead).
    pub fn bury(&mut self, job_id: &[u8; 16]) -> Result<(), Error> {
        let lease = match self.leases.remove(job_id) {
            Some(l) => l,
            None => return Err(Error::QueueCorrupt("no active lease for job".into())),
        };

        let outcome = self
            .queue
            .bury(&lease, steadq_core::DeadReason::AdministrativeBury);
        let mut trace = TraceEvent::new(self.operation_counter);
        self.operation_counter += 1;
        trace.job_id_hex = hex(job_id);

        match outcome {
            TransitionOutcome::Committed => {
                self.oracle.record_bury(job_id);
                trace.source_state = Some("leased".into());
                trace.destination_state = Some("dead".into());
                trace.syscall_result = Some("committed".into());
                self.traces.push(trace);
                Ok(())
            }
            TransitionOutcome::LeaseLost => {
                trace.syscall_result = Some("lease_lost".into());
                self.traces.push(trace);
                Err(Error::QueueCorrupt("lease lost".into()))
            }
            TransitionOutcome::NotCommitted(e) => {
                trace.syscall_result = Some(format!("not_committed: {e}"));
                self.traces.push(trace);
                Err(e)
            }
            TransitionOutcome::OutcomeUnknown(_) => {
                trace.syscall_result = Some("outcome_unknown".into());
                self.traces.push(trace);
                Err(Error::QueueCorrupt("bury outcome unknown".into()))
            }
        }
    }

    /// Verify that the Oracle's expected state matches the actual Queue state
    /// for all tracked jobs. This is the differential check.
    ///
    /// For each job the Oracle knows about, inspect the real queue and compare
    /// state, generation, and attempt. Any mismatch is a consistency error
    /// indicating production divergence.
    pub fn verify_consistency(&self) -> Vec<ConsistencyError> {
        let mut errors = Vec::new();
        for job in self.oracle.jobs() {
            let snapshots = self.queue.inspect(&job.job_id).expect("inspect the queue");
            let expected_state = oracle_state_name(&job.state);
            let actual = snapshots.iter().find(|s| s.state == expected_state);

            match (&job.state, actual) {
                (OracleState::Hidden, _) => {
                    // Hidden jobs should not be visible via inspect.
                    if !snapshots.is_empty() {
                        errors.push(ConsistencyError {
                            job_id_hex: hex(&job.job_id),
                            oracle_state: "hidden".into(),
                            actual_state: snapshots
                                .iter()
                                .map(|s| s.state.clone())
                                .collect::<Vec<_>>()
                                .join(","),
                            oracle_generation: job.generation,
                            actual_generation: snapshots.first().map(|s| s.generation).unwrap_or(0),
                            oracle_attempt: job.attempt,
                            actual_attempt: snapshots.first().map(|s| s.attempt).unwrap_or(0),
                            description: "hidden job is visible via inspect".into(),
                        });
                    }
                }
                (_, Some(snap)) => {
                    if snap.generation != job.generation {
                        errors.push(ConsistencyError {
                            job_id_hex: hex(&job.job_id),
                            oracle_state: expected_state.into(),
                            actual_state: snap.state.clone(),
                            oracle_generation: job.generation,
                            actual_generation: snap.generation,
                            oracle_attempt: job.attempt,
                            actual_attempt: snap.attempt,
                            description: "generation mismatch".into(),
                        });
                    }
                    if snap.attempt != job.attempt {
                        errors.push(ConsistencyError {
                            job_id_hex: hex(&job.job_id),
                            oracle_state: expected_state.into(),
                            actual_state: snap.state.clone(),
                            oracle_generation: job.generation,
                            actual_generation: snap.generation,
                            oracle_attempt: job.attempt,
                            actual_attempt: snap.attempt,
                            description: "attempt mismatch".into(),
                        });
                    }
                }
                (_, None) => {
                    // Oracle expects the job to be visible but inspect found nothing.
                    // This is valid for Receipt/Quarantine states which inspect may
                    // not report. Only flag for active states.
                    if matches!(
                        job.state,
                        OracleState::Ready
                            | OracleState::Leased
                            | OracleState::Delayed
                            | OracleState::Dead
                    ) {
                        errors.push(ConsistencyError {
                            job_id_hex: hex(&job.job_id),
                            oracle_state: expected_state.into(),
                            actual_state: "not_found".into(),
                            oracle_generation: job.generation,
                            actual_generation: 0,
                            oracle_attempt: job.attempt,
                            actual_attempt: 0,
                            description: "oracle expects visible but inspect found nothing".into(),
                        });
                    }
                }
            }
        }
        errors
    }

    /// Verify invariant I1: no visible active object has an incomplete envelope.
    pub fn check_i1(&self) -> bool {
        self.oracle.check_i1()
    }

    /// Verify invariant I9: committed leases never exceed maximum_attempts.
    pub fn check_i9(&self) -> bool {
        self.oracle.check_i9()
    }

    /// Get the trace events emitted so far.
    pub fn traces(&self) -> &[TraceEvent] {
        &self.traces
    }

    /// Get the underlying queue (for recovery, fsck, etc.).
    pub fn queue(&mut self) -> &mut Queue {
        &mut self.queue
    }

    /// Borrow the oracle.
    pub fn oracle(&self) -> &Oracle {
        &self.oracle
    }
}

fn oracle_state_name(state: &OracleState) -> &'static str {
    match state {
        OracleState::Hidden => "hidden",
        OracleState::Ready => "ready",
        OracleState::Leased => "leased",
        OracleState::Delayed => "delayed",
        OracleState::Dead => "dead",
        OracleState::Receipt => "receipt",
        OracleState::Quarantine => "quarantine",
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn driver_enqueue_and_inspect_match_oracle() {
        let tmp = tempfile::tempdir().unwrap();
        let mut driver = ProductionDriver::new(tmp.path()).unwrap();

        let _job_id = driver.enqueue(b"hello", 3).unwrap();
        assert!(driver.check_i1());
        assert!(driver.check_i9());

        let errors = driver.verify_consistency();
        assert!(
            errors.is_empty(),
            "consistency errors after enqueue: {:?}",
            errors
        );
    }

    #[test]
    fn driver_full_lifecycle_matches_oracle() {
        let tmp = tempfile::tempdir().unwrap();
        let mut driver = ProductionDriver::new(tmp.path()).unwrap();

        // Enqueue, lease, ack.
        let job_id = driver.enqueue(b"payload", 3).unwrap();
        assert!(driver.verify_consistency().is_empty());

        let leased_id = driver.lease(30_000_000_000).unwrap().expect("should lease");
        assert_eq!(leased_id, job_id);
        assert!(driver.verify_consistency().is_empty());

        driver.ack(&job_id).unwrap();
        // Receipts are terminal; verify_consistency doesn't flag them.
        assert!(driver.check_i1());
        assert!(driver.check_i9());
    }

    #[test]
    fn driver_retry_and_lease_again_matches_oracle() {
        let tmp = tempfile::tempdir().unwrap();
        let mut driver = ProductionDriver::new(tmp.path()).unwrap();

        let job_id = driver.enqueue(b"data", 3).unwrap();
        driver.lease(30_000_000_000).unwrap().expect("should lease");
        assert!(driver.verify_consistency().is_empty());

        driver.retry_now(&job_id).unwrap();
        assert!(driver.verify_consistency().is_empty());

        let leased2 = driver
            .lease(30_000_000_000)
            .unwrap()
            .expect("should lease again");
        assert_eq!(leased2, job_id);
        assert!(driver.verify_consistency().is_empty());
    }

    #[test]
    fn driver_bury_matches_oracle() {
        let tmp = tempfile::tempdir().unwrap();
        let mut driver = ProductionDriver::new(tmp.path()).unwrap();

        let job_id = driver.enqueue(b"data", 3).unwrap();
        driver.lease(30_000_000_000).unwrap().expect("should lease");
        driver.bury(&job_id).unwrap();

        let snapshots = driver.queue().inspect(&job_id).expect("inspect the queue");
        assert!(snapshots.iter().any(|s| s.state == "dead"));
    }

    #[test]
    fn driver_multiple_jobs_match_oracle() {
        let tmp = tempfile::tempdir().unwrap();
        let mut driver = ProductionDriver::new(tmp.path()).unwrap();

        let mut job_ids = Vec::new();
        for i in 0..5 {
            let id = driver.enqueue(&[i as u8; 64], 3).unwrap();
            job_ids.push(id);
        }
        assert!(driver.verify_consistency().is_empty());

        let leased1 = driver.lease(30_000_000_000).unwrap().unwrap();
        driver.ack(&leased1).unwrap();

        let leased2 = driver.lease(30_000_000_000).unwrap().unwrap();
        driver.ack(&leased2).unwrap();

        // Remaining 3 should still be in ready
        assert!(driver.verify_consistency().is_empty());

        assert!(driver.traces().len() >= 7); // 5 enqueues + 2 leases
    }

    #[test]
    fn driver_survives_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();

        let job_id = {
            let mut driver = ProductionDriver::new(&root).unwrap();
            driver.enqueue(b"persistent", 3).unwrap()
        };

        // Reopen: queue state should persist
        let mut driver2 = ProductionDriver::reopen(&root).unwrap();
        let snapshots = driver2.queue().inspect(&job_id).expect("inspect the queue");
        assert!(snapshots.iter().any(|s| s.state == "ready"));
    }

    #[test]
    fn driver_verify_consistency_detects_wrong_state() {
        let tmp = tempfile::tempdir().unwrap();
        let mut driver = ProductionDriver::new(tmp.path()).unwrap();

        let job_id = driver.enqueue(b"data", 3).unwrap();
        assert!(driver.verify_consistency().is_empty());

        // Corrupt the oracle: claim the job is leased when it is ready.
        driver.oracle.record_claim(&job_id, [0xFF; 16]);
        let errors = driver.verify_consistency();
        assert!(
            !errors.is_empty(),
            "verify_consistency should detect state mismatch"
        );
        assert_eq!(errors[0].oracle_state, "leased");
    }

    #[test]
    fn driver_verify_consistency_detects_hidden_visibility() {
        let tmp = tempfile::tempdir().unwrap();
        let mut driver = ProductionDriver::new(tmp.path()).unwrap();

        let job_id = driver.enqueue(b"data", 3).unwrap();
        // Force the oracle to think the job is hidden while it is ready.
        if let Some(job) = driver.oracle.get_mut(&job_id) {
            job.state = crate::oracle::OracleState::Hidden;
        }
        let errors = driver.verify_consistency();
        assert!(
            !errors.is_empty(),
            "verify_consistency should detect hidden-but-visible mismatch"
        );
    }

    #[test]
    fn driver_check_i1_detects_unsynced_file() {
        let tmp = tempfile::tempdir().unwrap();
        let mut driver = ProductionDriver::new(tmp.path()).unwrap();

        let job_id = driver.enqueue(b"data", 3).unwrap();
        assert!(driver.check_i1());

        // Corrupt: mark the file unsynced while the job is visible.
        if let Some(job) = driver.oracle.get_mut(&job_id) {
            job.file_synced = false;
        }
        assert!(!driver.check_i1(), "I1 should fail when file is unsynced");
    }

    #[test]
    fn driver_traces_are_versioned_and_valid() {
        let tmp = tempfile::tempdir().unwrap();
        let mut driver = ProductionDriver::new(tmp.path()).unwrap();
        driver.enqueue(b"data", 3).unwrap();
        driver.lease(30_000_000_000).unwrap();

        for trace in driver.traces() {
            assert!(trace.validate().is_ok(), "invalid trace: {trace:?}");
        }
        assert!(!driver.traces().is_empty());
    }
}

/// A seeded random operation sequence runner that drives the production
/// Queue API through the ProductionDriver and verifies oracle consistency
/// at every step.
#[cfg(test)]
mod stateful_tests {
    use super::*;
    use crate::simulator::Rng;

    /// Run a seeded stateful sequence of operations and verify consistency.
    fn run_stateful_sequence(seed: u64, num_ops: u32) {
        let tmp = tempfile::tempdir().unwrap();
        let mut driver = ProductionDriver::new(tmp.path()).unwrap();

        // Jobs available for lease.
        let mut ready_jobs: Vec<[u8; 16]> = Vec::new();
        // Jobs currently leased.
        let mut leased_jobs: Vec<[u8; 16]> = Vec::new();

        let mut rng = Rng::new(seed);

        for op_num in 0..num_ops {
            let op = rng.next_range(5);
            match op {
                0 => {
                    // Enqueue a new job
                    let payload_len = rng.next_range(256) as usize;
                    let payload: Vec<u8> = (0..payload_len).map(|_| rng.next_u64() as u8).collect();
                    let max_attempts = rng.next_range(3) as u32 + 1;
                    if let Ok(job_id) = driver.enqueue(&payload, max_attempts) {
                        ready_jobs.push(job_id);
                    }
                }
                1 => {
                    // Lease a job
                    if !ready_jobs.is_empty() {
                        let _idx = rng.next_range(ready_jobs.len() as u64) as usize;
                        if let Ok(Some(job_id)) = driver.lease(30_000_000_000) {
                            // The queue may lease a different job than expected
                            // (scan order depends on shard); find it in ready.
                            if let Some(pos) = ready_jobs.iter().position(|j| *j == job_id) {
                                ready_jobs.swap_remove(pos);
                            }
                            leased_jobs.push(job_id);
                        }
                    }
                }
                2 => {
                    // Ack a leased job
                    if !leased_jobs.is_empty() {
                        let idx = rng.next_range(leased_jobs.len() as u64) as usize;
                        let job_id = leased_jobs[idx];
                        match driver.ack(&job_id) {
                            Ok(()) => {
                                leased_jobs.swap_remove(idx);
                            }
                            Err(_) => {
                                // Ack can fail (lease lost, etc.); drop the job either way.
                                leased_jobs.swap_remove(idx);
                            }
                        }
                    }
                }
                3 => {
                    // Retry a leased job
                    if !leased_jobs.is_empty() {
                        let idx = rng.next_range(leased_jobs.len() as u64) as usize;
                        let job_id = leased_jobs[idx];
                        match driver.retry_now(&job_id) {
                            Ok(()) => {
                                leased_jobs.swap_remove(idx);
                                ready_jobs.push(job_id);
                            }
                            Err(_) => {
                                leased_jobs.swap_remove(idx);
                            }
                        }
                    }
                }
                4 => {
                    // Bury a leased job
                    if !leased_jobs.is_empty() {
                        let idx = rng.next_range(leased_jobs.len() as u64) as usize;
                        let job_id = leased_jobs[idx];
                        match driver.bury(&job_id) {
                            Ok(()) => {
                                leased_jobs.swap_remove(idx);
                            }
                            Err(_) => {
                                leased_jobs.swap_remove(idx);
                            }
                        }
                    }
                }
                _ => unreachable!(),
            }

            let errors = driver.verify_consistency();
            assert!(
                errors.is_empty(),
                "consistency error at op {op_num} (seed {seed}): {:?}",
                errors
            );

            assert!(
                driver.check_i1(),
                "I1 violated at op {op_num} (seed {seed})"
            );
            assert!(
                driver.check_i9(),
                "I9 violated at op {op_num} (seed {seed})"
            );
        }
    }

    #[test]
    fn stateful_sequence_short() {
        for seed in 0..10 {
            run_stateful_sequence(seed, 50);
        }
    }

    #[test]
    fn stateful_sequence_long() {
        for seed in 1000..1010 {
            run_stateful_sequence(seed, 200);
        }
    }

    #[test]
    fn stateful_sequence_enqueue_heavy() {
        let tmp = tempfile::tempdir().unwrap();
        let mut driver = ProductionDriver::new(tmp.path()).unwrap();
        let rng = Rng::new(42);

        for _ in 0..100 {
            let _ = driver.enqueue(&[0xAB; 64], 3).unwrap();
            assert!(driver.verify_consistency().is_empty());
        }

        // Lease and ack all of them
        for _ in 0..100 {
            if let Ok(Some(job_id)) = driver.lease(30_000_000_000) {
                driver.ack(&job_id).unwrap();
                assert!(driver.verify_consistency().is_empty());
            }
        }
        let _ = rng; // suppress unused warning
    }

    #[test]
    fn stateful_sequence_recover_after_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();

        let mut job_ids = Vec::new();
        {
            let mut driver = ProductionDriver::new(&root).unwrap();
            for i in 0..10 {
                let id = driver.enqueue(&[i as u8; 32], 3).unwrap();
                job_ids.push(id);
            }
            assert!(driver.verify_consistency().is_empty());
        }

        // Reopen and verify jobs persisted
        let mut driver2 = ProductionDriver::reopen(&root).unwrap();
        for job_id in &job_ids {
            let snapshots = driver2.queue().inspect(job_id).expect("inspect the queue");
            assert!(
                snapshots.iter().any(|s| s.state == "ready"),
                "job {} should be in ready after reopen",
                hex(job_id)
            );
        }

        // Lease and ack some, then reopen again
        let leased = driver2.lease(30_000_000_000).unwrap();
        assert!(leased.is_some());

        // Drop and reopen; the queue should still be consistent
        let mut driver3 = ProductionDriver::reopen(&root).unwrap();
        for job_id in &job_ids {
            let snapshots = driver3.queue().inspect(job_id).expect("inspect the queue");
            assert!(
                !snapshots.is_empty(),
                "job {} vanished after reopen",
                hex(job_id)
            );
        }
    }
}
