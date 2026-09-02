// Strict batch handle for group commit.
use super::*;

/// Strict batch for group commit. Operations are Pending until `commit`
/// fsyncs every exact dirty directory once. Post-linearization failures
/// become OutcomeUnknown.
pub struct Batch<'a> {
    pub(super) queue: &'a mut Queue,
    dirty: engine::DirtySet,
    pending_enqueues: Vec<EnqueueTicket>,
    pending_leases: usize,
    pending_acks: usize,
}

impl<'a> Batch<'a> {
    pub(super) fn new(queue: &'a mut Queue) -> Self {
        Self {
            queue,
            dirty: engine::DirtySet::new(),
            pending_enqueues: Vec::new(),
            pending_leases: 0,
            pending_acks: 0,
        }
    }
}

#[derive(Debug)]
pub enum BatchEnqueueOutcome {
    Pending(EnqueueTicket),
    NotCommitted(EnqueueTicket, Error),
    OutcomeUnknown(EnqueueTicket, Error),
}

#[derive(Debug)]
pub enum BatchLeaseOutcome {
    Pending(LeaseInfo),
    Empty,
    NotCommitted(Error),
    OutcomeUnknown(TransitionTicket),
}

#[derive(Debug)]
pub enum BatchAckOutcome {
    Pending,
    NotCommitted(Error),
    OutcomeUnknown(TransitionTicket),
}

pub(super) struct PreparedEnqueue {
    pub(super) ticket: EnqueueTicket,
    pub(super) header: FixedHeader,
    pub(super) ext_bytes: Vec<u8>,
    pub(super) payload: Vec<u8>,
    pub(super) dest_dir: String,
    pub(super) filename: String,
    pub(super) ready_shard_hint: Option<u32>,
}

#[derive(Debug)]
pub struct BatchCommitOutcome {
    pub committed_enqueues: Vec<EnqueueTicket>,
    pub outcome_unknown_enqueues: Vec<(EnqueueTicket, Error)>,
    pub committed_leases: usize,
    pub outcome_unknown_leases: Vec<Error>,
    pub committed_acks: usize,
    pub outcome_unknown_acks: Vec<Error>,
}

impl<'a> Batch<'a> {
    /// Enqueue within the batch. The job is Pending until `commit`.
    /// Batches dir fsyncs — file writes and publishes happen immediately
    /// but dest dirs are recorded and flushed once at commit.
    pub fn enqueue(&mut self, input: EnqueueInput) -> BatchEnqueueOutcome {
        match self.queue.enqueue_batched(input, &mut self.dirty) {
            EnqueueOutcome::Committed(ticket) => {
                self.pending_enqueues.push(ticket.clone());
                BatchEnqueueOutcome::Pending(ticket)
            }
            EnqueueOutcome::Deferred(ticket) => {
                self.pending_enqueues.push(ticket.clone());
                BatchEnqueueOutcome::Pending(ticket)
            }
            EnqueueOutcome::NotCommitted(ticket, err) => {
                BatchEnqueueOutcome::NotCommitted(ticket, err)
            }
            EnqueueOutcome::OutcomeUnknown(ticket, err) => {
                BatchEnqueueOutcome::OutcomeUnknown(ticket, err)
            }
        }
    }

    /// Lease within the batch.
    pub fn lease(&mut self, max_wait_ns: u64, lease_duration_ns: u64) -> BatchLeaseOutcome {
        match self
            .queue
            .lease_batched(max_wait_ns, lease_duration_ns, &mut self.dirty)
        {
            LeaseOutcome::Leased(info) => {
                self.pending_leases += 1;
                BatchLeaseOutcome::Pending(info)
            }
            LeaseOutcome::Empty => BatchLeaseOutcome::Empty,
            LeaseOutcome::NotCommitted(err) => BatchLeaseOutcome::NotCommitted(err),
            LeaseOutcome::OutcomeUnknown(ticket) => BatchLeaseOutcome::OutcomeUnknown(ticket),
        }
    }

    /// Verify a pending lease's payload before additional batch work.
    pub fn verify_lease_payload(&self, lease: &LeaseInfo) -> Result<(), Error> {
        self.queue.verify_lease_payload(lease)
    }

    /// Ack within the batch.
    pub fn ack(&mut self, lease: &LeaseInfo) -> BatchAckOutcome {
        match self.queue.ack_batched(lease, &mut self.dirty) {
            AckOutcome::Acked => {
                self.pending_acks += 1;
                BatchAckOutcome::Pending
            }
            AckOutcome::AlreadyAcked => BatchAckOutcome::Pending,
            AckOutcome::LeaseLost => {
                BatchAckOutcome::NotCommitted(Error::InvalidInput("lease lost".into()))
            }
            AckOutcome::NotCommitted(err) => BatchAckOutcome::NotCommitted(err),
            AckOutcome::OutcomeUnknown(ticket) => BatchAckOutcome::OutcomeUnknown(ticket),
        }
    }

    /// Commit the batch: fsync every exact dirty directory once.
    /// If the barrier fails, all pending post-linearization ops become OutcomeUnknown.
    pub fn commit(self) -> Result<BatchCommitOutcome, BatchCommitOutcome> {
        let Batch {
            queue,
            dirty,
            pending_enqueues,
            pending_leases,
            pending_acks,
        } = self;

        let sync_result = dirty.sync_all();

        if let Err(e) = sync_result {
            queue.poison(PoisonReason::PostLinearizationStateUnknown);
            let e = Error::from(e);
            let outcome = BatchCommitOutcome {
                committed_enqueues: Vec::new(),
                outcome_unknown_enqueues: pending_enqueues
                    .into_iter()
                    .map(|t| (t, e.clone()))
                    .collect(),
                committed_leases: 0,
                outcome_unknown_leases: (0..pending_leases).map(|_| e.clone()).collect(),
                committed_acks: 0,
                outcome_unknown_acks: (0..pending_acks).map(|_| e.clone()).collect(),
            };
            return Err(outcome);
        }

        Ok(BatchCommitOutcome {
            committed_enqueues: pending_enqueues,
            outcome_unknown_enqueues: Vec::new(),
            committed_leases: pending_leases,
            outcome_unknown_leases: Vec::new(),
            committed_acks: pending_acks,
            outcome_unknown_acks: Vec::new(),
        })
    }
}
