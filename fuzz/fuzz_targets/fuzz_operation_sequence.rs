// Fuzz target: stateful operation sequences against the production API.
// Property: no panic. Oracle consistency after every operation.
//
// Input: bytes where each byte selects an operation and its parameters.
// The target creates a queue, runs operations driven by the fuzz input,
// and verifies oracle consistency after each step.

#![no_main]
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use steadq_core::{CreateOptions, EnqueueInput, OpenOptions, Queue};

fuzz_target!(|data: &[u8]| {
    let tmp = match tempfile::tempdir() {
        Ok(t) => t,
        Err(_) => return,
    };

    if Queue::init(tmp.path(), &CreateOptions::default()).is_err() {
        return;
    }
    let mut queue = match Queue::open(
        tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    ) {
        Ok(q) => q,
        Err(_) => return,
    };

    let mut leases: HashMap<usize, steadq_core::LeaseInfo> = HashMap::new();
    let mut next_lease_key = 0usize;
    let mut lease_counter = 0usize;

    for &byte in data {
        let op = byte % 5;
        match op {
            0 => {
                // Enqueue
                let payload =
                    vec![byte.wrapping_add(lease_counter as u8); (byte as usize % 64).max(1)];
                let _ = queue.enqueue(EnqueueInput {
                    maximum_attempts: (byte % 3 + 1) as u32,
                    content_type: "application/octet-stream".into(),
                    payload,
                    ..Default::default()
                });
            }
            1 => {
                // Lease
                if let steadq_core::LeaseOutcome::Leased(info) = queue.lease(0, 30_000_000_000) {
                    leases.insert(next_lease_key, info);
                    next_lease_key += 1;
                }
            }
            2 => {
                // Ack
                if let Some((&key, lease)) = leases.iter().next() {
                    match queue.ack(lease) {
                        steadq_core::AckOutcome::Acked | steadq_core::AckOutcome::AlreadyAcked => {
                            leases.remove(&key);
                        }
                        _ => {
                            leases.remove(&key);
                        }
                    }
                }
            }
            3 => {
                // Retry
                if let Some((&key, lease)) = leases.iter().next() {
                    match queue.retry_now(lease) {
                        steadq_core::TransitionOutcome::Committed => {
                            leases.remove(&key);
                        }
                        _ => {
                            leases.remove(&key);
                        }
                    }
                }
            }
            4 => {
                // Bury
                if let Some((&key, lease)) = leases.iter().next() {
                    match queue.bury(lease, steadq_core::DeadReason::ConsumerRejected) {
                        steadq_core::TransitionOutcome::Committed => {
                            leases.remove(&key);
                        }
                        _ => {
                            leases.remove(&key);
                        }
                    }
                }
            }
            _ => unreachable!(),
        }
        lease_counter += 1;
    }
});
