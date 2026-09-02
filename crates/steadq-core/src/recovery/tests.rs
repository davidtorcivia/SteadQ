// Unit tests for recovery.
use super::*;
use crate::queue::engine::{ReplacePhase, UnlinkPhase};
use crate::{AckOutcome, CreateOptions, EnqueueInput, LeaseOutcome, OpenOptions};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn create_test_queue() -> (TempDir, Queue) {
    create_test_queue_with_shards(CreateOptions::default().shard_count)
}

fn create_test_queue_with_shards(shard_count: u32) -> (TempDir, Queue) {
    let tmp = TempDir::new().unwrap();
    fs::fault::pin_clock_realtime_ns(fs::clock_realtime_ns().unwrap());
    Queue::init(
        tmp.path(),
        &CreateOptions {
            shard_count,
            ..Default::default()
        },
    )
    .unwrap();
    let queue = Queue::open(
        tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    )
    .unwrap();
    (tmp, queue)
}

#[test]
fn empty_directory_removal_requires_every_observed_child_to_be_absent() {
    for (absent, observed, expected) in [
        (0, 0, true),
        (0, 1, false),
        (1, 1, true),
        (1, 2, false),
        (2, 1, false),
    ] {
        assert_eq!(
            all_observed_children_absent(absent, observed),
            expected,
            "absent={absent} observed={observed}"
        );
    }
}

#[test]
fn recovery_quarantine_records_identity_and_failure_context() {
    let (tmp, queue) = create_test_queue();
    std::fs::write(tmp.path().join("candidate.raw"), b"candidate").unwrap();
    let mut stats = RecoveryStats::default();
    queue.quarantine_recovery_object(
        RecoveryQuarantineCandidate {
            source_directory_fd: queue.root_fd(),
            filename: "candidate.raw",
            relative_path: "ready/00000000/candidate.raw",
            reason: crate::QuarantineReason::EnvelopeCorrupt,
        },
        &mut stats,
        &WorkBudget::default(),
    );
    assert_eq!(stats.operations_attempted, 1);
    assert!(stats.errors.is_empty());
    assert_eq!(stats.quarantined.len(), 1);
    let quarantined = &stats.quarantined[0];
    assert_eq!(quarantined.relative_path, "ready/00000000/candidate.raw");
    assert!(tmp
        .path()
        .join("quarantine")
        .join(&quarantined.quarantine_name)
        .exists());
    assert_eq!(
        steadq_names::parse_quarantine(&quarantined.quarantine_name)
            .unwrap()
            .quarantine_id,
        quarantined.quarantine_id
    );

    std::fs::write(tmp.path().join("failure.raw"), b"failure").unwrap();
    let mut failed = RecoveryStats::default();
    fs::fault::reset();
    fs::fault::inject_errno("get_random", 1, libc::EIO);
    queue.quarantine_recovery_object(
        RecoveryQuarantineCandidate {
            source_directory_fd: queue.root_fd(),
            filename: "failure.raw",
            relative_path: "delayed/0000000000000000/00000000/failure.raw",
            reason: crate::QuarantineReason::EnvelopeCorrupt,
        },
        &mut failed,
        &WorkBudget::default(),
    );
    fs::fault::reset();
    assert_eq!(failed.operations_attempted, 0);
    assert!(failed.quarantined.is_empty());
    assert_eq!(failed.errors.len(), 1);
    assert_eq!(failed.errors[0].operation, "quarantine");
    assert_eq!(
        failed.errors[0].relative_path,
        "delayed/0000000000000000/00000000/failure.raw"
    );
    assert!(failed.errors[0].error.contains("phase=RandomName"));
    assert!(tmp.path().join("failure.raw").exists());
}

#[test]
fn recovery_quarantine_collision_consumes_budget_and_replays() {
    let (tmp, queue) = create_test_queue();
    let collision_id = [0x31; 16];
    let replay_id = [0x32; 16];
    let reason = crate::QuarantineReason::EnvelopeCorrupt;
    let collision_name = steadq_names::quarantine_filename(&collision_id, reason as u16);
    std::fs::write(tmp.path().join("candidate.raw"), b"candidate").unwrap();
    std::fs::write(
        tmp.path().join("quarantine").join(&collision_name),
        b"distinct",
    )
    .unwrap();

    let mut exhausted = RecoveryStats::default();
    let completed = queue.quarantine_recovery_object_with_ids(
        RecoveryQuarantineCandidate {
            source_directory_fd: queue.root_fd(),
            filename: "candidate.raw",
            relative_path: "ready/00000000/candidate.raw",
            reason,
        },
        &mut exhausted,
        &WorkBudget {
            max_operations: 1,
            ..WorkBudget::default()
        },
        || Ok(collision_id),
    );
    assert!(!completed);
    assert_eq!(exhausted.operations_attempted, 1);
    assert!(exhausted.budget_exhausted);
    assert!(exhausted.quarantined.is_empty());
    assert_eq!(exhausted.errors.len(), 1);
    assert_eq!(exhausted.errors[0].operation, "quarantine_budget_exhausted");
    assert_eq!(
        std::fs::read(tmp.path().join("candidate.raw")).unwrap(),
        b"candidate"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("quarantine").join(&collision_name)).unwrap(),
        b"distinct"
    );

    let mut replayed = RecoveryStats::default();
    let mut ids = [collision_id, replay_id].into_iter();
    let completed = queue.quarantine_recovery_object_with_ids(
        RecoveryQuarantineCandidate {
            source_directory_fd: queue.root_fd(),
            filename: "candidate.raw",
            relative_path: "ready/00000000/candidate.raw",
            reason,
        },
        &mut replayed,
        &WorkBudget {
            max_operations: 2,
            ..WorkBudget::default()
        },
        || Ok(ids.next().unwrap()),
    );
    assert!(completed);
    assert_eq!(replayed.operations_attempted, 2);
    assert!(!replayed.budget_exhausted);
    assert!(replayed.errors.is_empty());
    assert_eq!(replayed.quarantined.len(), 1);
    assert_eq!(replayed.quarantined[0].quarantine_id, replay_id);
    assert!(!tmp.path().join("candidate.raw").exists());
    assert_eq!(
        std::fs::read(tmp.path().join("quarantine").join(collision_name)).unwrap(),
        b"distinct"
    );
}

#[test]
fn recovery_quarantine_budget_exhaustion_does_not_advance_cursor() {
    let (tmp, mut queue) = create_test_queue();
    let width = queue.format.delayed_bucket_width_ns();
    let not_before = queue
        .authenticated_wall_floor()
        .unwrap()
        .unix_ns()
        .checked_add(width)
        .unwrap();
    let ticket = match queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".into(),
        initial_not_before: Some(not_before),
        payload: b"corrupt delayed".to_vec(),
        ..Default::default()
    }) {
        EnqueueOutcome::Committed(ticket) => ticket,
        outcome => panic!("enqueue failed: {outcome:?}"),
    };
    let source = tmp.path().join(&ticket.expected_relative_path);
    let mut corrupt = std::fs::read(&source).unwrap();
    corrupt[0] ^= 0xff;
    std::fs::write(&source, corrupt).unwrap();
    let eligible_bucket = steadq_math::ceiling_bucket(not_before, width).unwrap();
    write_wall_watermark(&tmp, eligible_bucket);
    let wall_floor = queue.authenticated_wall_floor().unwrap();
    let scan_budget = RecoveryScanBudget::default();
    let mut scan_stats = RecoveryScanStats::default();
    let mut scan = RecoveryScanContext {
        budget: &scan_budget,
        stats: &mut scan_stats,
    };
    let mut stats = RecoveryStats::default();

    fs::fault::reset();
    fs::fault::inject_errno("renameat2_noreplace", 1, libc::EEXIST);
    queue.promote_delayed(
        wall_floor,
        &WorkBudget {
            max_operations: 1,
            ..WorkBudget::default()
        },
        &mut scan,
        &mut stats,
        u64::MAX,
    );
    fs::fault::reset();

    assert_eq!(stats.operations_attempted, 1, "stats: {stats:?}");
    assert!(stats.budget_exhausted, "stats: {stats:?}");
    assert!(stats.quarantined.is_empty());
    assert_eq!(queue.recovery_cursor.promote_delayed, None);
    assert!(source.exists());

    queue.persist_recovery_cursor().unwrap();
    drop(queue);
    let mut reopened = Queue::open(
        tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    )
    .unwrap();
    let replay_floor = reopened.authenticated_wall_floor().unwrap();
    let replay = promote_eligible_with_budget(&mut reopened, replay_floor);
    assert_eq!(replay.operations_attempted, 1);
    assert_eq!(replay.quarantined.len(), 1, "errors: {:?}", replay.errors);
    assert!(!source.exists());
}

fn enqueue_for_shard(
    queue: &mut Queue,
    tmp: &TempDir,
    target_shard: u32,
    initial_not_before: Option<u64>,
    payload: &[u8],
) -> EnqueueTicket {
    for _ in 0..128 {
        let ticket = match queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".into(),
            initial_not_before,
            payload: payload.to_vec(),
            ..Default::default()
        }) {
            EnqueueOutcome::Committed(ticket) => ticket,
            outcome => panic!("enqueue failed: {outcome:?}"),
        };
        let shard = ticket
            .expected_relative_path
            .rsplit('/')
            .nth(1)
            .and_then(steadq_names::shard_from_hex)
            .unwrap();
        if shard == target_shard {
            return ticket;
        }
        std::fs::remove_file(tmp.path().join(&ticket.expected_relative_path)).unwrap();
    }
    panic!("failed to enqueue a job in shard {target_shard}");
}

fn ack_for_shard(queue: &mut Queue, tmp: &TempDir, target_shard: u32, payload: &[u8]) {
    enqueue_for_shard(queue, tmp, target_shard, None, payload);
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(lease) => lease,
        outcome => panic!("lease failed: {outcome:?}"),
    };
    assert!(matches!(queue.ack(&lease), AckOutcome::Acked));
}

fn hierarchical_receipts(tmp: &TempDir, queue: &mut Queue) -> Vec<PathBuf> {
    for (shard, payload) in [(0, b"low-a"), (0, b"low-b"), (1, b"low-c")] {
        ack_for_shard(queue, tmp, shard, payload);
    }
    let mut low_receipts = Vec::new();
    find_files(&tmp.path().join("receipts"), "rct", &mut low_receipts);
    let low_terminal_bucket = low_receipts[0]
        .strip_prefix(tmp.path().join("receipts"))
        .unwrap()
        .components()
        .next()
        .unwrap()
        .as_os_str()
        .to_str()
        .and_then(steadq_names::bucket_from_hex)
        .unwrap();
    let delayed_buckets_per_terminal = queue
        .format
        .terminal_bucket_width_ns()
        .checked_div(queue.format.delayed_bucket_width_ns())
        .unwrap();
    let high_floor_bucket = low_terminal_bucket
        .checked_add(2)
        .and_then(|bucket| bucket.checked_mul(delayed_buckets_per_terminal))
        .unwrap();
    write_wall_watermark(tmp, high_floor_bucket);
    queue.cached_wall_floor = None;
    for (shard, payload) in [(0, b"high-a"), (1, b"high-b")] {
        ack_for_shard(queue, tmp, shard, payload);
    }

    let mut receipts = Vec::new();
    find_files(&tmp.path().join("receipts"), "rct", &mut receipts);
    receipts.sort();
    receipts
}

fn find_file(root: &Path, extension: &str) -> Option<PathBuf> {
    for entry in std::fs::read_dir(root).ok()? {
        let path = entry.ok()?.path();
        if path.is_dir() {
            if let Some(found) = find_file(&path, extension) {
                return Some(found);
            }
        } else if path.extension().and_then(|value| value.to_str()) == Some(extension) {
            return Some(path);
        }
    }
    None
}

fn relocate_colocated_leases_into_legacy_tree(root: &Path, queue: &Queue) {
    let width = queue.format.lease_bucket_width_ns();
    for shard in 0..queue.format.shard_count() {
        let ready_dir = root.join(format!("ready/{}", steadq_names::shard_hex(shard)));
        let Ok(entries) = std::fs::read_dir(&ready_dir) else {
            continue;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            let Ok(parsed) = steadq_names::parse_leased(name) else {
                continue;
            };
            let boot = steadq_names::format_boot_id(&parsed.boot_id);
            let bucket = steadq_math::lease_bucket(parsed.boottime_deadline_ns, width).unwrap();
            let dest_dir = root.join(format!(
                "leased/{}/{}/{}",
                boot,
                steadq_names::bucket_hex(bucket),
                steadq_names::shard_hex(shard)
            ));
            std::fs::create_dir_all(&dest_dir).unwrap();
            std::fs::rename(&path, dest_dir.join(name)).unwrap();
        }
    }
}

fn find_files(root: &Path, extension: &str, found: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            find_files(&path, extension, found);
        } else if path.extension().and_then(|value| value.to_str()) == Some(extension) {
            found.push(path);
        }
    }
}

fn find_compaction_temporary_files(root: &Path, found: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            find_compaction_temporary_files(&path, found);
        } else if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(compaction_temporary_name)
        {
            found.push(path);
        }
    }
}

fn write_wall_watermark(tmp: &TempDir, highest_observed_bucket: u64) {
    let path = tmp.path().join("control/wall-watermark");
    let bytes = std::fs::read(&path).unwrap();
    let current = steadq_format::WatermarkRecord::decode(&bytes).unwrap();
    let updated = steadq_format::WatermarkRecord {
        highest_observed_bucket,
        sequence: current.sequence.checked_add(1).unwrap(),
    };
    std::fs::write(path, updated.encode()).unwrap();
}

fn enqueue_and_ack(queue: &mut Queue) -> crate::LeaseInfo {
    assert!(matches!(
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".into(),
            payload: b"receipt".to_vec(),
            ..Default::default()
        }),
        EnqueueOutcome::Committed(_)
    ));
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(lease) => lease,
        outcome => panic!("lease failed: {outcome:?}"),
    };
    assert!(matches!(queue.ack(&lease), AckOutcome::Acked));
    lease
}

fn lease_recovery_job(queue: &mut Queue, maximum_attempts: u32) -> crate::LeaseInfo {
    assert!(matches!(
        queue.enqueue(EnqueueInput {
            maximum_attempts,
            content_type: "x".into(),
            payload: b"recovery move".to_vec(),
            ..Default::default()
        }),
        EnqueueOutcome::Committed(_)
    ));
    match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(lease) => lease,
        outcome => panic!("lease failed: {outcome:?}"),
    }
}

fn lease_common(lease: &crate::LeaseInfo) -> steadq_names::CommonFields {
    steadq_names::CommonFields {
        job_id: lease.job_id,
        generation: lease.generation,
        attempt: lease.attempt,
        maximum_attempts: lease.maximum_attempts,
    }
}

fn lease_path_parts(lease: &crate::LeaseInfo) -> Vec<&str> {
    let parts = lease.exact_source_path.split('/').collect::<Vec<_>>();
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[0], "ready");
    parts
}

fn ready_destination(queue: &Queue, shard: &str, common: &steadq_names::CommonFields) -> String {
    let ready_common = steadq_names::CommonFields {
        job_id: common.job_id,
        generation: common.generation.checked_add(1).unwrap(),
        attempt: common.attempt,
        maximum_attempts: common.maximum_attempts,
    };
    format!(
        "ready/{shard}/{}",
        steadq_names::make_ready_name(queue.format.queue_id(), shard, &ready_common)
    )
}

fn dead_destination(
    queue: &Queue,
    shard: &str,
    common: &steadq_names::CommonFields,
    wall_floor: WallFloor,
) -> String {
    let terminal_bucket = steadq_math::bucket_number(
        wall_floor.unix_ns(),
        queue.format.terminal_bucket_width_ns(),
    )
    .unwrap();
    let bucket = steadq_names::bucket_hex(terminal_bucket);
    let dead_common = steadq_names::CommonFields {
        job_id: common.job_id,
        generation: common.generation.checked_add(1).unwrap(),
        attempt: common.attempt,
        maximum_attempts: common.maximum_attempts,
    };
    format!(
        "dead/{bucket}/{shard}/{}",
        steadq_names::make_dead_name(
            queue.format.queue_id(),
            &bucket,
            shard,
            &dead_common,
            DeadReason::AttemptsExhausted as u16,
        )
    )
}

fn assert_injected_move_phase(
    result: Result<(), MoveFailure>,
    expected_phase: MovePhase,
    outcome_unknown: bool,
) {
    match result {
        Err(MoveFailure::OutcomeUnknown { phase, .. }) if outcome_unknown => {
            assert_eq!(phase, expected_phase)
        }
        Err(MoveFailure::NotCommitted { phase, .. }) if !outcome_unknown => {
            assert_eq!(phase, expected_phase)
        }
        result => panic!("unexpected move result: {result:?}"),
    }
}

fn assert_recorded_move_failure(
    stats: &RecoveryStats,
    operation: &str,
    expected_phase: MovePhase,
    outcome_unknown: bool,
) {
    let expected_operation = format!(
        "{operation}_{}",
        if outcome_unknown {
            "outcome_unknown"
        } else {
            "not_committed"
        }
    );
    assert_eq!(stats.operations_attempted, 1);
    assert_eq!(stats.errors.len(), 1, "errors: {:?}", stats.errors);
    assert_eq!(stats.errors[0].operation, expected_operation);
    assert!(
        stats.errors[0]
            .error
            .contains(&format!("phase={expected_phase:?}")),
        "errors: {:?}",
        stats.errors
    );
}

fn assert_recorded_move_category(stats: &RecoveryStats, operation: &str, category: &str) {
    assert_eq!(stats.operations_attempted, 1);
    assert_eq!(stats.errors.len(), 1, "errors: {:?}", stats.errors);
    assert_eq!(stats.errors[0].operation, format!("{operation}_{category}"));
    assert!(stats.errors[0].error.contains("phase=Rename"));
}

fn reap_expired_with_budget(queue: &mut Queue, budget: &WorkBudget) -> RecoveryStats {
    let scan_budget = RecoveryScanBudget::default();
    let mut scan_stats = RecoveryScanStats::default();
    let mut scan = RecoveryScanContext {
        budget: &scan_budget,
        stats: &mut scan_stats,
    };
    let mut stats = RecoveryStats::default();
    queue.reap_expired_leases(
        u64::MAX,
        Some(queue.authenticated_wall_floor().unwrap()),
        budget,
        &mut scan,
        &mut stats,
        u64::MAX,
    );
    stats
}

fn promote_eligible_with_budget(queue: &mut Queue, wall_floor: WallFloor) -> RecoveryStats {
    let scan_budget = RecoveryScanBudget::default();
    let mut scan_stats = RecoveryScanStats::default();
    let mut scan = RecoveryScanContext {
        budget: &scan_budget,
        stats: &mut scan_stats,
    };
    let mut stats = RecoveryStats::default();
    queue.promote_delayed(
        wall_floor,
        &WorkBudget::default(),
        &mut scan,
        &mut stats,
        u64::MAX,
    );
    stats
}

fn cleanup_temp_with_budget(queue: &mut Queue) -> RecoveryStats {
    let scan_budget = RecoveryScanBudget::default();
    let mut scan_stats = RecoveryScanStats::default();
    let mut scan = RecoveryScanContext {
        budget: &scan_budget,
        stats: &mut scan_stats,
    };
    let mut stats = RecoveryStats::default();
    queue.cleanup_temp_files(
        u64::MAX,
        &WorkBudget::default(),
        &mut scan,
        &mut stats,
        u64::MAX,
    );
    stats
}

fn compact_receipts_with_budget(queue: &mut Queue) -> RecoveryStats {
    let scan_budget = RecoveryScanBudget::default();
    let mut scan_stats = RecoveryScanStats::default();
    let mut scan = RecoveryScanContext {
        budget: &scan_budget,
        stats: &mut scan_stats,
    };
    let mut stats = RecoveryStats::default();
    queue.compact_receipts_with_scan_budget(
        &WorkBudget::default(),
        &mut scan,
        &mut stats,
        u64::MAX,
    );
    stats
}

fn delete_receipts_with_budget(queue: &mut Queue, wall_floor: WallFloor) -> RecoveryStats {
    let scan_budget = RecoveryScanBudget::default();
    let mut scan_stats = RecoveryScanStats::default();
    let mut scan = RecoveryScanContext {
        budget: &scan_budget,
        stats: &mut scan_stats,
    };
    let mut stats = RecoveryStats::default();
    queue.delete_expired_receipts(
        wall_floor,
        0,
        &WorkBudget::default(),
        &mut scan,
        &mut stats,
        u64::MAX,
    );
    stats
}

fn assert_recorded_unlink_failure(
    stats: &RecoveryStats,
    operation: &str,
    phase: UnlinkPhase,
    outcome_unknown: bool,
) {
    let expected_operation = format!(
        "{operation}_{}",
        if outcome_unknown {
            "outcome_unknown"
        } else {
            "not_committed"
        }
    );
    assert_eq!(stats.operations_attempted, 1);
    assert_eq!(stats.errors.len(), 1, "errors: {:?}", stats.errors);
    assert_eq!(stats.errors[0].operation, expected_operation);
    assert!(
        stats.errors[0].error.contains(&format!("phase={phase:?}")),
        "errors: {:?}",
        stats.errors
    );
}

fn assert_recorded_remove_directory_failure(
    stats: &RecoveryStats,
    operation: &str,
    relative_path: &str,
    phase: crate::queue::engine::RemoveDirectoryPhase,
    outcome_unknown: bool,
) {
    let expected_operation = format!(
        "{operation}_{}",
        if outcome_unknown {
            "outcome_unknown"
        } else {
            "not_committed"
        }
    );
    assert_eq!(stats.operations_attempted, 1, "stats: {stats:?}");
    assert_eq!(stats.errors.len(), 1, "errors: {:?}", stats.errors);
    assert_eq!(stats.errors[0].operation, expected_operation);
    assert_eq!(stats.errors[0].relative_path, relative_path);
    assert!(
        stats.errors[0].error.contains(&format!("phase={phase:?}")),
        "errors: {:?}",
        stats.errors
    );
}

fn retry_next_hierarchy_directory(
    queue: &mut Queue,
    phase: RecoveryPhase,
    phase_root_fd: BorrowedFd<'_>,
    scan: &mut RecoveryScanContext<'_>,
    stats: &mut RecoveryStats,
    deadline_mono: u64,
) -> bool {
    let retry = queue.next_hierarchy_retry(phase);
    queue.retry_one_hierarchy_directory(phase, retry, phase_root_fd, scan, stats, deadline_mono)
}

const RECOVERY_READ_PERMUTATIONS: [(usize, bool); 5] =
    [(1, false), (0, true), (2, true), (3, false), (4, true)];

fn open_with_readdir_permutation(tmp: &TempDir, options: &OpenOptions, pass: usize) -> Queue {
    let queue = Queue::open(tmp.path(), options).unwrap();
    fs::fault::reset();
    let (rotation, reversed) = RECOVERY_READ_PERMUTATIONS[pass];
    fs::fault::permute_readdir(rotation, reversed);
    queue
}

fn assert_removed_prefix(paths: &[PathBuf], pass: usize) {
    for (index, path) in paths.iter().enumerate() {
        assert_eq!(
            path.exists(),
            index > pass,
            "pass={pass} index={index} path={}",
            path.display()
        );
    }
}

fn assert_compacted_prefix(paths: &[PathBuf], pass: usize) {
    for (index, path) in paths.iter().enumerate() {
        let length = std::fs::metadata(path).unwrap().len();
        assert_eq!(
            length == steadq_format::COMPACT_RECEIPT_SIZE as u64,
            index <= pass,
            "pass={pass} index={index} path={} length={length}",
            path.display()
        );
    }
}

fn hierarchy_components(root: &Path, paths: &[PathBuf]) -> Vec<Vec<String>> {
    paths
        .iter()
        .map(|path| {
            path.strip_prefix(root)
                .unwrap()
                .components()
                .map(|component| component.as_os_str().to_str().unwrap().to_string())
                .collect()
        })
        .collect()
}

fn assert_three_level_fixture(root: &Path, paths: &[PathBuf]) {
    let parts = hierarchy_components(root, paths);
    assert_eq!(parts.len(), RECOVERY_READ_PERMUTATIONS.len());
    assert_eq!(parts[0][..2], parts[1][..2]);
    assert_ne!(parts[0][2], parts[1][2]);
    assert_eq!(parts[1][0], parts[2][0]);
    assert_ne!(parts[1][1], parts[2][1]);
    assert_ne!(parts[2][0], parts[3][0]);
    assert_eq!(parts[3][0], parts[4][0]);
    assert_ne!(parts[3][1], parts[4][1]);
}

fn assert_four_level_fixture(root: &Path, paths: &[PathBuf]) {
    let parts = hierarchy_components(root, paths);
    assert_eq!(parts.len(), RECOVERY_READ_PERMUTATIONS.len());
    assert_eq!(parts[0][..3], parts[1][..3]);
    assert_ne!(parts[0][3], parts[1][3]);
    assert_eq!(parts[1][..2], parts[2][..2]);
    assert_ne!(parts[1][2], parts[2][2]);
    assert_eq!(parts[2][0], parts[3][0]);
    assert_ne!(parts[2][1], parts[3][1]);
    assert_ne!(parts[3][0], parts[4][0]);
}

fn valid_cursor_record(queue: &Queue) -> RecoveryCursorRecord {
    RecoveryCursorRecord {
        schema: RECOVERY_CURSOR_SCHEMA.into(),
        version: RECOVERY_CURSOR_VERSION,
        queue_id: steadq_names::hex_encode(queue.format.queue_id()),
        cursor: RecoveryCursor::default(),
    }
}

#[test]
fn recovery_phase_budget_table() {
    let mut stats = RecoveryStats::default();
    assert!(Queue::has_recovery_budget(&stats));
    stats.budget_exhausted = true;
    assert!(!Queue::has_recovery_budget(&stats));
    stats.budget_exhausted = false;
    stats.phase_blocked = true;
    assert!(Queue::has_recovery_budget(&stats));
}

#[test]
fn recovery_scan_bounds_are_fixed_and_finite() {
    assert_eq!(MAX_RECOVERY_DIRECTORY_ENTRIES, 65_536);
    assert_eq!(MAX_RECOVERY_DIRECTORY_NAME_BYTES, 16_711_680);
    assert_eq!(MAX_RECOVERY_DIRECTORY_ENTRY_CHARGE, 65_537);
    assert_eq!(MAX_RECOVERY_DIRECTORY_NAME_BYTE_CHARGE, 16_711_935);
    assert_eq!(MAX_RECOVERY_RESUMED_TRAVERSAL_READS, 4);
    assert_eq!(RECOVERY_RETRY_READS, 1);
    assert_eq!(MIN_RECOVERY_PROGRESS_READS, 5);
    assert_eq!(MIN_RECOVERY_PROGRESS_ENTRIES, 327_681);
    assert_eq!(MIN_RECOVERY_PROGRESS_NAME_BYTES, 83_558_655);
    assert_eq!(DEFAULT_RECOVERY_DIRECTORY_READS, 1024);
    assert_eq!(
        RecoveryScanBudget::default().max_directories_read,
        DEFAULT_RECOVERY_DIRECTORY_READS
    );
    assert_eq!(
        RecoveryScanBudget::default().max_entries_read,
        RecoveryScanBudget::minimum_for_progress().max_entries_read
    );
    assert_eq!(
        RecoveryScanBudget::default().max_name_bytes_read,
        RecoveryScanBudget::minimum_for_progress().max_name_bytes_read
    );
}

#[test]
fn recovery_public_budget_validation_requires_progress_headroom() {
    assert!(RecoveryScanBudget::minimum_for_progress()
        .validate()
        .is_ok());

    for budget in [
        RecoveryScanBudget {
            max_directories_read: MIN_RECOVERY_PROGRESS_READS - 1,
            ..RecoveryScanBudget::minimum_for_progress()
        },
        RecoveryScanBudget {
            max_entries_read: MIN_RECOVERY_PROGRESS_ENTRIES - 1,
            ..RecoveryScanBudget::minimum_for_progress()
        },
        RecoveryScanBudget {
            max_name_bytes_read: MIN_RECOVERY_PROGRESS_NAME_BYTES - 1,
            ..RecoveryScanBudget::minimum_for_progress()
        },
    ] {
        assert!(matches!(budget.validate(), Err(Error::InvalidInput(_))));
    }
}

#[test]
fn recovery_rejects_invalid_budget_before_filesystem_work() {
    let (_tmp, mut queue) = create_test_queue();
    for scan_budget in [
        RecoveryScanBudget {
            max_directories_read: MIN_RECOVERY_PROGRESS_READS - 1,
            ..RecoveryScanBudget::minimum_for_progress()
        },
        RecoveryScanBudget {
            max_entries_read: MIN_RECOVERY_PROGRESS_ENTRIES - 1,
            ..RecoveryScanBudget::minimum_for_progress()
        },
        RecoveryScanBudget {
            max_name_bytes_read: MIN_RECOVERY_PROGRESS_NAME_BYTES - 1,
            ..RecoveryScanBudget::minimum_for_progress()
        },
    ] {
        fs::fault::reset();
        let report = queue.recover_with_scan_budget(&WorkBudget::default(), &scan_budget);

        assert!(report.stats.phase_blocked);
        assert_eq!(report.stats.errors.len(), 1);
        assert_eq!(report.stats.errors[0].operation, "recovery_scan_budget");
        assert_eq!(report.scan.directories_read, 0);
        assert_eq!(report.scan.entries_read, 0);
        assert_eq!(report.scan.name_bytes_read, 0);
        assert_eq!(fs::fault::call_count("open_directory"), 0);
    }
}

#[test]
fn recovery_retries_before_resuming_the_deepest_cursor() {
    let (tmp, mut queue) = create_test_queue();
    let cursor_boot = "00000000-0000-0000-0000-000000000001";
    let later_boot = "00000000-0000-0000-0000-000000000002";
    let retry_boot = "00000000-0000-0000-0000-000000000003";
    let bucket = "0000000000000000";
    let shard = "0000";
    let leaf_entry = "z-classified-after-retry";
    std::fs::create_dir_all(
        tmp.path()
            .join(format!("leased/{cursor_boot}/{bucket}/{shard}")),
    )
    .unwrap();
    std::fs::write(
        tmp.path().join(format!(
            "leased/{cursor_boot}/{bucket}/{shard}/{leaf_entry}"
        )),
        b"not a protocol object",
    )
    .unwrap();
    std::fs::create_dir_all(tmp.path().join(format!("leased/{later_boot}"))).unwrap();
    std::fs::create_dir_all(tmp.path().join(format!("leased/{retry_boot}"))).unwrap();

    queue.recovery_cursor.phase = RecoveryPhase::ReapLeases;
    queue.recovery_cursor.reap_leases = Some(FourLevelCursor::new(
        cursor_boot.as_bytes(),
        bucket.as_bytes(),
        shard.as_bytes(),
        b"processed.sqj",
    ));
    assert_eq!(
        queue.remember_hierarchy_retry(
            RecoveryPhase::ReapLeases,
            RecoveryHierarchyRetryKind::Enumerate,
            &[retry_boot.as_bytes()],
        ),
        RememberHierarchyRetry::Exact
    );
    queue.persist_recovery_cursor().unwrap();
    drop(queue);

    let mut reopened = Queue::open(
        tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    )
    .unwrap();
    let report = reopened.recover_with_scan_budget(
        &WorkBudget::default(),
        &RecoveryScanBudget::minimum_for_progress(),
    );
    assert!(report.stats.budget_exhausted);
    assert_eq!(report.scan.directories_read, MIN_RECOVERY_PROGRESS_READS);
    assert!(reopened.recovery_cursor.hierarchy_retries.is_empty());
    let expected_cursor = FourLevelCursor::new(
        cursor_boot.as_bytes(),
        bucket.as_bytes(),
        shard.as_bytes(),
        leaf_entry.as_bytes(),
    );
    assert_eq!(
        reopened.recovery_cursor.reap_leases,
        Some(expected_cursor.clone())
    );
    drop(reopened);

    let reopened = Queue::open(
        tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(reopened.recovery_cursor.hierarchy_retries.is_empty());
    assert_eq!(reopened.recovery_cursor.reap_leases, Some(expected_cursor));
}

#[test]
fn recovery_work_budget_predicate_covers_operation_time_and_clock_failure() {
    fs::fault::reset();
    assert!(Queue::budget_time_exceeded(0).unwrap());
    assert!(!Queue::budget_time_exceeded(u64::MAX).unwrap());

    let budget = WorkBudget {
        max_operations: 1,
        max_duration_ms: u64::MAX,
    };
    let mut stats = RecoveryStats::default();
    assert!(!Queue::work_budget_exhausted(&mut stats, &budget, u64::MAX));
    stats.operations_attempted = 1;
    assert!(Queue::work_budget_exhausted(&mut stats, &budget, u64::MAX));
    stats.operations_attempted = 0;
    assert!(Queue::work_budget_exhausted(&mut stats, &budget, 0));

    fs::fault::inject("clock_monotonic_ns", 1);
    assert!(Queue::work_budget_exhausted(&mut stats, &budget, u64::MAX));
    fs::fault::reset();
    assert!(stats.phase_blocked);
    assert!(stats
        .errors
        .iter()
        .any(|error| error.operation == "clock_monotonic"));
}

#[test]
fn recovery_error_helpers_preserve_context_and_block_state() {
    let mut stats = RecoveryStats::default();
    Queue::record_error(&mut stats, "operation", "path", "error");
    assert_eq!(stats.errors.len(), 1);
    assert_eq!(stats.errors[0].operation, "operation");
    assert_eq!(stats.errors[0].relative_path, "path");
    assert_eq!(stats.errors[0].error, "error");
    assert!(!stats.phase_blocked);

    Queue::block_phase(&mut stats, "blocked", "blocked-path", "blocked-error");
    assert!(stats.phase_blocked);
    assert_eq!(stats.errors.len(), 2);
    assert_eq!(stats.errors[1].operation, "blocked");
    assert_eq!(stats.errors[1].relative_path, "blocked-path");
    assert_eq!(stats.errors[1].error, "blocked-error");

    let mut timed_out = RecoveryStats::default();
    assert!(Queue::record_directory_error(
        &mut timed_out,
        "read",
        "directory",
        &RecoveryDirectoryError::BudgetExhausted,
    ));
    assert!(timed_out.budget_exhausted);
    assert!(!timed_out.phase_blocked);
    assert!(timed_out.errors.is_empty());

    let mut io_failed = RecoveryStats::default();
    assert!(!Queue::record_directory_error(
        &mut io_failed,
        "read",
        "directory",
        &RecoveryDirectoryError::Io(io::Error::from_raw_os_error(libc::ETIMEDOUT)),
    ));
    assert!(!io_failed.budget_exhausted);
    assert!(io_failed.phase_blocked);
    assert_eq!(io_failed.errors.len(), 1);
    assert_eq!(io_failed.errors[0].operation, "read");

    let mut clock_failed = RecoveryStats::default();
    assert!(Queue::record_directory_error(
        &mut clock_failed,
        "read",
        "directory",
        &RecoveryDirectoryError::Clock(io::Error::from_raw_os_error(libc::EIO)),
    ));
    assert!(clock_failed.budget_exhausted);
    assert!(!Queue::has_recovery_budget(&clock_failed));
    assert!(clock_failed.phase_blocked);
    assert_eq!(clock_failed.errors.len(), 1);
    assert_eq!(clock_failed.errors[0].operation, "clock_monotonic");
}

#[test]
fn recovery_phase_progress_prevents_early_phase_starvation_after_reopen() {
    let (tmp, mut queue) = create_test_queue();
    enqueue_and_ack(&mut queue);

    let budget = WorkBudget {
        max_operations: 1,
        max_duration_ms: 5_000,
    };
    let first = queue.recover(&budget);
    assert_eq!(first.operations_attempted, 1, "errors: {:?}", first.errors);
    assert_eq!(first.leases_reaped, 0, "errors: {:?}", first.errors);
    assert!(first.budget_exhausted);
    assert_eq!(queue.recovery_cursor.phase, RecoveryPhase::DeleteReceipts);
    drop(queue);

    let mut reopened = Queue::open(
        tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        reopened.recovery_cursor.phase,
        RecoveryPhase::DeleteReceipts
    );

    let second = reopened.recover(&budget);
    assert_eq!(
        second.operations_attempted, 0,
        "errors: {:?}",
        second.errors
    );
    assert_eq!(reopened.recovery_cursor.phase, RecoveryPhase::ReapLeases);
}

#[test]
fn recovery_reloads_cursor_after_lock_acquisition() {
    let (tmp, mut first) = create_test_queue();
    let mut stale = Queue::open(
        tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    )
    .unwrap();
    enqueue_and_ack(&mut first);
    enqueue_and_ack(&mut first);
    let mut receipts = Vec::new();
    find_files(&tmp.path().join("receipts"), "rct", &mut receipts);
    receipts.sort();
    let budget = WorkBudget {
        max_operations: 1,
        max_duration_ms: 5_000,
    };

    let first_stats = first.recover(&budget);
    assert!(first_stats.budget_exhausted);
    assert_eq!(first_stats.receipts_compacted, 1);
    assert_eq!(std::fs::metadata(&receipts[0]).unwrap().len(), 128);

    let stale_stats = stale.recover(&budget);
    assert_eq!(stale_stats.receipts_compacted, 1);
    assert_eq!(std::fs::metadata(&receipts[1]).unwrap().len(), 128);
}

#[test]
fn persistent_hierarchy_open_failure_does_not_starve_later_sibling_across_reopen() {
    use std::os::unix::fs::symlink;

    let (tmp, mut queue) = create_test_queue();
    assert!(matches!(
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".into(),
            payload: b"later work".to_vec(),
            ..Default::default()
        }),
        EnqueueOutcome::Committed(_)
    ));
    assert!(matches!(
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".into(),
            payload: b"second later work".to_vec(),
            ..Default::default()
        }),
        EnqueueOutcome::Committed(_)
    ));
    assert!(matches!(
        queue.lease(0, 30_000_000_000),
        LeaseOutcome::Leased(_)
    ));
    assert!(matches!(
        queue.lease(0, 30_000_000_000),
        LeaseOutcome::Leased(_)
    ));
    relocate_colocated_leases_into_legacy_tree(tmp.path(), &queue);
    let blocked = tmp
        .path()
        .join("leased/00000000-0000-0000-0000-000000000000");
    symlink(tmp.path(), &blocked).unwrap();
    let budget = WorkBudget {
        max_operations: 1,
        max_duration_ms: 5_000,
    };

    let first = reap_expired_with_budget(&mut queue, &budget);
    assert!(first.phase_blocked);
    assert!(first.budget_exhausted);
    assert_eq!(first.scan_skips, 1);
    assert_eq!(first.leases_reaped, 1, "errors: {:?}", first.errors);
    assert!(first
        .errors
        .iter()
        .any(|error| error.operation == "reap_boot_open"));
    assert!(queue.recovery_cursor.reap_leases.is_some());
    assert_eq!(queue.recovery_cursor.hierarchy_retries.len(), 1);
    assert_eq!(
        queue.recovery_cursor.hierarchy_retries[0],
        RecoveryHierarchyRetry {
            phase: RecoveryPhase::ReapLeases,
            kind: RecoveryHierarchyRetryKind::Open,
            components: vec!["00000000-0000-0000-0000-000000000000".into()],
        }
    );
    queue.persist_recovery_cursor().unwrap();
    drop(queue);

    let mut reopened = Queue::open(
        tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(reopened.recovery_cursor.reap_leases.is_some());
    assert_eq!(reopened.recovery_cursor.hierarchy_retries.len(), 1);
    let second = reap_expired_with_budget(&mut reopened, &budget);
    assert!(second.phase_blocked);
    assert_eq!(second.scan_skips, 1);
    assert_eq!(second.leases_reaped, 1, "errors: {:?}", second.errors);
    assert!(second
        .errors
        .iter()
        .any(|error| error.operation == "hierarchy_retry_open"));
    assert!(blocked.is_symlink());

    std::fs::remove_file(&blocked).unwrap();
    let third = reap_expired_with_budget(&mut reopened, &WorkBudget::default());
    assert!(!third.phase_blocked, "errors: {:?}", third.errors);
    assert!(reopened.recovery_cursor.hierarchy_retries.is_empty());
}

#[test]
fn persistent_bucket_open_failure_does_not_starve_receipt_compaction() {
    use std::os::unix::fs::symlink;

    let (tmp, mut queue) = create_test_queue();
    enqueue_and_ack(&mut queue);
    enqueue_and_ack(&mut queue);
    let blocked = tmp.path().join("receipts/0000000000000000");
    symlink(tmp.path(), &blocked).unwrap();
    let budget = WorkBudget {
        max_operations: 1,
        max_duration_ms: 5_000,
    };
    let scan_budget = RecoveryScanBudget {
        max_directories_read: MIN_RECOVERY_PROGRESS_READS * 20,
        max_entries_read: MAX_RECOVERY_DIRECTORY_ENTRY_CHARGE * 20,
        max_name_bytes_read: MAX_RECOVERY_DIRECTORY_NAME_BYTE_CHARGE * 20,
    };
    queue.recovery_cursor.phase = RecoveryPhase::CompactReceipts;
    queue.persist_recovery_cursor().unwrap();

    let first = queue.recover_with_scan_budget(&budget, &scan_budget).stats;
    assert!(first.phase_blocked);
    assert!(first.budget_exhausted);
    assert_eq!(first.scan_skips, 1);
    assert_eq!(first.receipts_compacted, 1, "errors: {:?}", first.errors);
    assert!(first
        .errors
        .iter()
        .any(|error| error.operation == "compact_bucket_open"));
    assert!(queue.recovery_cursor.compact_receipts.is_some());
    assert_eq!(queue.recovery_cursor.hierarchy_retries.len(), 1);
    assert_eq!(
        queue.recovery_cursor.hierarchy_retries[0],
        RecoveryHierarchyRetry {
            phase: RecoveryPhase::CompactReceipts,
            kind: RecoveryHierarchyRetryKind::Open,
            components: vec!["0000000000000000".into()],
        }
    );
    drop(queue);
    let mut reopened = Queue::open(
        tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(reopened.recovery_cursor.compact_receipts.is_some());
    assert_eq!(reopened.recovery_cursor.hierarchy_retries.len(), 1);
    let second = reopened
        .recover_with_scan_budget(&budget, &scan_budget)
        .stats;
    assert!(second.phase_blocked);
    assert_eq!(second.scan_skips, 1);
    assert_eq!(second.receipts_compacted, 1, "errors: {:?}", second.errors);
    assert!(second
        .errors
        .iter()
        .any(|error| error.operation == "hierarchy_retry_open"));
    assert!(blocked.is_symlink());
}

#[test]
fn delayed_shard_open_failure_is_counted_and_does_not_starve_later_shard() {
    use std::os::unix::fs::symlink;

    let (tmp, mut queue) = create_test_queue();
    let not_before = queue
        .authenticated_wall_floor()
        .unwrap()
        .unix_ns()
        .checked_add(queue.format.delayed_bucket_width_ns())
        .unwrap();
    let ticket = (0..128)
        .find_map(|_| {
            let ticket = match queue.enqueue(EnqueueInput {
                maximum_attempts: 3,
                content_type: "x".into(),
                initial_not_before: Some(not_before),
                payload: b"delayed later shard".to_vec(),
                ..Default::default()
            }) {
                EnqueueOutcome::Committed(ticket) => ticket,
                outcome => panic!("enqueue failed: {outcome:?}"),
            };
            let parts = ticket.expected_relative_path.split('/').collect::<Vec<_>>();
            if parts[2] != "0000" {
                return Some(ticket);
            }
            std::fs::remove_file(tmp.path().join(&ticket.expected_relative_path)).unwrap();
            std::fs::remove_dir(tmp.path().join(format!("delayed/{}/0000", parts[1]))).unwrap();
            None
        })
        .expect("128 random jobs must include a nonzero shard");
    let parts = ticket.expected_relative_path.split('/').collect::<Vec<_>>();
    let bucket = parts[1];
    let blocked = tmp.path().join(format!("delayed/{bucket}/0000"));
    if blocked.exists() {
        std::fs::remove_dir(&blocked).unwrap();
    }
    symlink(tmp.path(), &blocked).unwrap();
    write_wall_watermark(&tmp, steadq_names::bucket_from_hex(bucket).unwrap());

    let scan_budget = RecoveryScanBudget::default();
    let mut scan_stats = RecoveryScanStats::default();
    let mut scan = RecoveryScanContext {
        budget: &scan_budget,
        stats: &mut scan_stats,
    };
    let mut stats = RecoveryStats::default();
    queue.promote_delayed(
        queue.authenticated_wall_floor().unwrap(),
        &WorkBudget::default(),
        &mut scan,
        &mut stats,
        u64::MAX,
    );

    assert!(stats.phase_blocked);
    assert_eq!(stats.scan_skips, 1);
    assert_eq!(stats.delayed_promoted, 1, "errors: {:?}", stats.errors);
    assert!(stats
        .errors
        .iter()
        .any(|error| error.operation == "promote_shard_open"));
    assert!(!tmp.path().join(ticket.expected_relative_path).exists());
    assert!(blocked.is_symlink());
}

#[test]
fn readdir_permutations_preserve_reap_budget_boundaries() {
    let (tmp, mut queue) = create_test_queue_with_shards(2);
    // 30s leases must share a bucket; 130s must not. Pin boottime so a
    // 10s width boundary cannot move between those leases.
    fs::fault::set_clock_boottime_ns(1_000_000_000_000);
    let first_boot = "00000000-0000-0000-0000-000000000001";
    let second_boot = "00000000-0000-0000-0000-000000000002";
    for (boot, duration, shard, payload) in [
        (first_boot, 30_000_000_000, 0, b"reap-a" as &[u8]),
        (first_boot, 30_000_000_000, 0, b"reap-b" as &[u8]),
        (first_boot, 30_000_000_000, 1, b"reap-c" as &[u8]),
        (first_boot, 130_000_000_000, 0, b"reap-d" as &[u8]),
        (second_boot, 30_000_000_000, 0, b"reap-e" as &[u8]),
    ] {
        queue.boot_id = boot.into();
        enqueue_for_shard(&mut queue, &tmp, shard, None, payload);
        assert!(matches!(queue.lease(0, duration), LeaseOutcome::Leased(_)));
    }
    relocate_colocated_leases_into_legacy_tree(tmp.path(), &queue);
    let mut leased = Vec::new();
    find_files(&tmp.path().join("leased"), "sqj", &mut leased);
    leased.sort();
    assert_four_level_fixture(&tmp.path().join("leased"), &leased);
    fs::fault::reset();
    drop(queue);

    let options = OpenOptions {
        allow_unsupported_fs: true,
        ..Default::default()
    };
    let budget = WorkBudget {
        max_operations: 1,
        max_duration_ms: 5_000,
    };
    let mut queue = open_with_readdir_permutation(&tmp, &options, 0);
    let zero = reap_expired_with_budget(
        &mut queue,
        &WorkBudget {
            max_operations: 0,
            max_duration_ms: 5_000,
        },
    );
    fs::fault::reset();
    assert_eq!(zero.operations_attempted, 0);
    queue.persist_recovery_cursor().unwrap();
    drop(queue);
    assert!(leased.iter().all(|path| path.exists()));

    for pass in 0..RECOVERY_READ_PERMUTATIONS.len() {
        let mut queue = open_with_readdir_permutation(&tmp, &options, pass);
        let stats = reap_expired_with_budget(&mut queue, &budget);
        fs::fault::reset();
        assert_eq!(stats.operations_attempted, 1, "pass={pass}");
        assert_eq!(
            stats.leases_reaped, 1,
            "pass={pass} errors={:?}",
            stats.errors
        );
        queue.persist_recovery_cursor().unwrap();
        drop(queue);
        assert_removed_prefix(&leased, pass);
    }
}

#[test]
fn readdir_permutations_preserve_promotion_budget_boundaries() {
    let (tmp, mut queue) = create_test_queue_with_shards(2);
    let low_not_before = queue
        .authenticated_wall_floor()
        .unwrap()
        .unix_ns()
        .checked_add(queue.format.delayed_bucket_width_ns() * 4)
        .unwrap();
    let high_not_before = low_not_before
        .checked_add(queue.format.delayed_bucket_width_ns() * 4)
        .unwrap();
    for (not_before, shard, payload) in [
        (low_not_before, 0, b"promote-a" as &[u8]),
        (low_not_before, 0, b"promote-b" as &[u8]),
        (low_not_before, 1, b"promote-c" as &[u8]),
        (high_not_before, 0, b"promote-d" as &[u8]),
        (high_not_before, 1, b"promote-e" as &[u8]),
    ] {
        enqueue_for_shard(&mut queue, &tmp, shard, Some(not_before), payload);
    }
    let mut delayed = Vec::new();
    find_files(&tmp.path().join("delayed"), "sqj", &mut delayed);
    delayed.sort();
    assert_three_level_fixture(&tmp.path().join("delayed"), &delayed);
    let delayed_bucket = delayed
        .iter()
        .map(|path| {
            path.strip_prefix(tmp.path().join("delayed"))
                .unwrap()
                .components()
                .next()
                .unwrap()
                .as_os_str()
                .to_str()
                .and_then(steadq_names::bucket_from_hex)
                .unwrap()
        })
        .max()
        .unwrap();
    write_wall_watermark(&tmp, delayed_bucket);
    drop(queue);

    let options = OpenOptions {
        allow_unsupported_fs: true,
        ..Default::default()
    };
    let budget = WorkBudget {
        max_operations: 1,
        max_duration_ms: 5_000,
    };
    let mut queue = open_with_readdir_permutation(&tmp, &options, 0);
    let scan_budget = RecoveryScanBudget::default();
    let mut scan_stats = RecoveryScanStats::default();
    let mut scan = RecoveryScanContext {
        budget: &scan_budget,
        stats: &mut scan_stats,
    };
    let mut zero = RecoveryStats::default();
    let wall_floor = queue.authenticated_wall_floor().unwrap();
    queue.promote_delayed(
        wall_floor,
        &WorkBudget {
            max_operations: 0,
            max_duration_ms: 5_000,
        },
        &mut scan,
        &mut zero,
        u64::MAX,
    );
    fs::fault::reset();
    assert_eq!(zero.operations_attempted, 0);
    queue.persist_recovery_cursor().unwrap();
    drop(queue);
    assert!(delayed.iter().all(|path| path.exists()));

    for pass in 0..RECOVERY_READ_PERMUTATIONS.len() {
        let mut queue = open_with_readdir_permutation(&tmp, &options, pass);
        let scan_budget = RecoveryScanBudget::default();
        let mut scan_stats = RecoveryScanStats::default();
        let mut scan = RecoveryScanContext {
            budget: &scan_budget,
            stats: &mut scan_stats,
        };
        let mut stats = RecoveryStats::default();
        let wall_floor = queue.authenticated_wall_floor().unwrap();
        queue.promote_delayed(wall_floor, &budget, &mut scan, &mut stats, u64::MAX);
        fs::fault::reset();
        assert_eq!(stats.operations_attempted, 1, "pass={pass}");
        assert_eq!(
            stats.delayed_promoted, 1,
            "pass={pass} errors={:?}",
            stats.errors
        );
        queue.persist_recovery_cursor().unwrap();
        drop(queue);
        assert_removed_prefix(&delayed, pass);
    }
}

#[test]
fn readdir_permutations_preserve_temp_cleanup_budget_boundaries() {
    let (tmp, queue) = create_test_queue_with_shards(2);
    let first_boot = "00000000-0000-0000-0000-000000000001";
    let second_boot = "00000000-0000-0000-0000-000000000002";
    assert_ne!(queue.boot_id, first_boot);
    assert_ne!(queue.boot_id, second_boot);
    let mut temp_paths = Vec::new();
    for (boot, shard, suffix) in [
        (first_boot, "0000", 0),
        (first_boot, "0000", 1),
        (first_boot, "0001", 2),
        (second_boot, "0000", 3),
        (second_boot, "0001", 4),
    ] {
        let directory = tmp.path().join(format!("tmp/{boot}/{shard}"));
        std::fs::create_dir_all(&directory).unwrap();
        let filename = steadq_names::temp_filename(0, &[suffix as u8; 16]);
        let path = directory.join(filename);
        std::fs::write(&path, b"temp").unwrap();
        temp_paths.push(path);
    }
    temp_paths.sort();
    assert_three_level_fixture(&tmp.path().join("tmp"), &temp_paths);
    drop(queue);

    let options = OpenOptions {
        allow_unsupported_fs: true,
        ..Default::default()
    };
    let budget = WorkBudget {
        max_operations: 1,
        max_duration_ms: 5_000,
    };
    let mut queue = open_with_readdir_permutation(&tmp, &options, 0);
    let scan_budget = RecoveryScanBudget::default();
    let mut scan_stats = RecoveryScanStats::default();
    let mut scan = RecoveryScanContext {
        budget: &scan_budget,
        stats: &mut scan_stats,
    };
    let mut zero = RecoveryStats::default();
    queue.cleanup_temp_files(
        u64::MAX,
        &WorkBudget {
            max_operations: 0,
            max_duration_ms: 5_000,
        },
        &mut scan,
        &mut zero,
        u64::MAX,
    );
    fs::fault::reset();
    assert_eq!(zero.operations_attempted, 0);
    queue.persist_recovery_cursor().unwrap();
    drop(queue);
    assert!(temp_paths.iter().all(|path| path.exists()));

    for pass in 0..RECOVERY_READ_PERMUTATIONS.len() {
        let mut queue = open_with_readdir_permutation(&tmp, &options, pass);
        let scan_budget = RecoveryScanBudget::default();
        let mut scan_stats = RecoveryScanStats::default();
        let mut scan = RecoveryScanContext {
            budget: &scan_budget,
            stats: &mut scan_stats,
        };
        let mut stats = RecoveryStats::default();
        queue.cleanup_temp_files(u64::MAX, &budget, &mut scan, &mut stats, u64::MAX);
        fs::fault::reset();
        assert_eq!(stats.operations_attempted, 1, "pass={pass}");
        assert_eq!(
            stats.temp_files_deleted, 1,
            "pass={pass} errors={:?}",
            stats.errors
        );
        queue.persist_recovery_cursor().unwrap();
        drop(queue);
        assert_removed_prefix(&temp_paths, pass);
    }
}

#[test]
fn readdir_permutations_preserve_compaction_budget_boundaries() {
    let (tmp, mut queue) = create_test_queue_with_shards(2);
    let receipts = hierarchical_receipts(&tmp, &mut queue);
    assert_three_level_fixture(&tmp.path().join("receipts"), &receipts);
    drop(queue);

    let options = OpenOptions {
        allow_unsupported_fs: true,
        ..Default::default()
    };
    let budget = WorkBudget {
        max_operations: 1,
        max_duration_ms: 5_000,
    };
    let mut queue = open_with_readdir_permutation(&tmp, &options, 0);
    let scan_budget = RecoveryScanBudget::default();
    let mut scan_stats = RecoveryScanStats::default();
    let mut scan = RecoveryScanContext {
        budget: &scan_budget,
        stats: &mut scan_stats,
    };
    let mut zero = RecoveryStats::default();
    queue.compact_receipts_with_scan_budget(
        &WorkBudget {
            max_operations: 0,
            max_duration_ms: 5_000,
        },
        &mut scan,
        &mut zero,
        u64::MAX,
    );
    fs::fault::reset();
    assert_eq!(zero.operations_attempted, 0);
    queue.persist_recovery_cursor().unwrap();
    drop(queue);
    assert!(receipts.iter().all(|path| {
        std::fs::metadata(path).unwrap().len() > steadq_format::COMPACT_RECEIPT_SIZE as u64
    }));

    for pass in 0..RECOVERY_READ_PERMUTATIONS.len() {
        let mut queue = open_with_readdir_permutation(&tmp, &options, pass);
        let scan_budget = RecoveryScanBudget::default();
        let mut scan_stats = RecoveryScanStats::default();
        let mut scan = RecoveryScanContext {
            budget: &scan_budget,
            stats: &mut scan_stats,
        };
        let mut stats = RecoveryStats::default();
        queue.compact_receipts_with_scan_budget(&budget, &mut scan, &mut stats, u64::MAX);
        fs::fault::reset();
        assert_eq!(stats.operations_attempted, 1, "pass={pass}");
        assert_eq!(
            stats.receipts_compacted, 1,
            "pass={pass} errors={:?}",
            stats.errors
        );
        queue.persist_recovery_cursor().unwrap();
        drop(queue);
        assert_compacted_prefix(&receipts, pass);
    }
}

#[test]
fn readdir_permutations_preserve_deletion_budget_boundaries() {
    let (tmp, mut queue) = create_test_queue_with_shards(2);
    let receipts = hierarchical_receipts(&tmp, &mut queue);
    assert_three_level_fixture(&tmp.path().join("receipts"), &receipts);
    let terminal_bucket = receipts
        .iter()
        .map(|path| {
            path.strip_prefix(tmp.path().join("receipts"))
                .unwrap()
                .components()
                .next()
                .unwrap()
                .as_os_str()
                .to_str()
                .and_then(steadq_names::bucket_from_hex)
                .unwrap()
        })
        .max()
        .unwrap();
    let delayed_buckets_per_terminal = queue
        .format
        .terminal_bucket_width_ns()
        .checked_div(queue.format.delayed_bucket_width_ns())
        .unwrap();
    let retention_floor_bucket = terminal_bucket
        .checked_add(1)
        .and_then(|bucket| bucket.checked_mul(delayed_buckets_per_terminal))
        .unwrap();
    write_wall_watermark(&tmp, retention_floor_bucket);
    drop(queue);

    let options = OpenOptions {
        allow_unsupported_fs: true,
        receipt_retention_ns: 0,
        ..Default::default()
    };
    let budget = WorkBudget {
        max_operations: 1,
        max_duration_ms: 5_000,
    };
    let mut queue = open_with_readdir_permutation(&tmp, &options, 0);
    let scan_budget = RecoveryScanBudget::default();
    let mut scan_stats = RecoveryScanStats::default();
    let mut scan = RecoveryScanContext {
        budget: &scan_budget,
        stats: &mut scan_stats,
    };
    let mut zero = RecoveryStats::default();
    let wall_floor = queue.authenticated_wall_floor().unwrap();
    queue.delete_expired_receipts(
        wall_floor,
        0,
        &WorkBudget {
            max_operations: 0,
            max_duration_ms: 5_000,
        },
        &mut scan,
        &mut zero,
        u64::MAX,
    );
    fs::fault::reset();
    assert_eq!(zero.operations_attempted, 0);
    queue.persist_recovery_cursor().unwrap();
    drop(queue);
    assert!(receipts.iter().all(|path| path.exists()));

    let mut receipt_pass = 0usize;
    for pass in 0..(receipts.len() * 3) {
        let mut queue =
            open_with_readdir_permutation(&tmp, &options, pass % RECOVERY_READ_PERMUTATIONS.len());
        let scan_budget = RecoveryScanBudget::default();
        let mut scan_stats = RecoveryScanStats::default();
        let mut scan = RecoveryScanContext {
            budget: &scan_budget,
            stats: &mut scan_stats,
        };
        let mut stats = RecoveryStats::default();
        let wall_floor = queue.authenticated_wall_floor().unwrap();
        queue.delete_expired_receipts(wall_floor, 0, &budget, &mut scan, &mut stats, u64::MAX);
        fs::fault::reset();
        assert_eq!(stats.operations_attempted, 1, "pass={pass}");
        assert!(stats.errors.is_empty(), "pass={pass}: {:?}", stats.errors);
        if stats.receipts_expired == 1 {
            assert_eq!(stats.shards_removed, 0, "pass={pass}");
            assert_eq!(stats.buckets_removed, 0, "pass={pass}");
            assert_removed_prefix(&receipts, receipt_pass);
            receipt_pass += 1;
        } else {
            assert_eq!(stats.receipts_expired, 0, "pass={pass}");
            assert_eq!(
                stats.shards_removed + stats.buckets_removed,
                1,
                "pass={pass}"
            );
        }
        queue.persist_recovery_cursor().unwrap();
        drop(queue);
        if receipt_pass == receipts.len() {
            break;
        }
    }
    assert_eq!(receipt_pass, receipts.len());
}

#[test]
fn scan_cursor_skips_only_canonical_processed_prefix() {
    let cursor = ThreeLevelCursor::new(b"0002", b"0003", b"middle.rct");
    for (bucket, shard, entry, expected) in [
        ("0001", "ffff", "later.rct", true),
        ("0002", "0002", "later.rct", true),
        ("0002", "0003", "earlier.rct", true),
        ("0002", "0003", "middle.rct", true),
        ("0002", "0003", "z-later.rct", false),
        ("0002", "0004", "earlier.rct", false),
        ("0003", "0000", "earlier.rct", false),
    ] {
        assert_eq!(
            cursor.should_skip(bucket.as_bytes(), shard.as_bytes(), entry.as_bytes()),
            expected
        );
    }
}

#[test]
fn scan_cursor_preserves_non_utf8_order_exactly() {
    let cursor = ThreeLevelCursor::new(b"0002", b"0003", b"bad-\x80.rct");
    assert!(cursor.should_skip(b"0002", b"0003", b"bad-\x80.rct"));
    assert!(!cursor.should_skip(b"0002", b"0003", b"bad-\x81.rct"));
    let encoded = serde_json::to_vec(&cursor).unwrap();
    let decoded: ThreeLevelCursor = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded, cursor);
}

#[test]
fn four_level_cursor_skips_only_canonical_processed_prefix() {
    let cursor = FourLevelCursor::new(b"boot-b", b"0002", b"0003", b"middle.sqj");
    for (first, second, third, entry, expected) in [
        ("boot-a", "ffff", "ffff", "later.sqj", true),
        ("boot-b", "0001", "ffff", "later.sqj", true),
        ("boot-b", "0002", "0002", "later.sqj", true),
        ("boot-b", "0002", "0003", "middle.sqj", true),
        ("boot-b", "0002", "0003", "z-later.sqj", false),
        ("boot-b", "0002", "0004", "earlier.sqj", false),
        ("boot-c", "0000", "0000", "earlier.sqj", false),
    ] {
        assert_eq!(
            cursor.should_skip(
                first.as_bytes(),
                second.as_bytes(),
                third.as_bytes(),
                entry.as_bytes(),
            ),
            expected
        );
    }
}

#[test]
fn recovery_cursor_component_validation_table() {
    for (component, expected) in [
        ("0000", true),
        ("job.rct", true),
        ("", false),
        (".", false),
        ("..", false),
        ("a/b", false),
        ("a\0b", false),
    ] {
        assert_eq!(cursor_component_is_valid(component.as_bytes()), expected);
    }
    assert!(!cursor_component_is_valid("x".repeat(256).as_bytes()));
}

#[test]
fn recovery_cursor_validation_checks_every_component() {
    let valid_three = ThreeLevelCursor::new(b"first", b"second", b"entry");
    let valid_four = FourLevelCursor::new(b"first", b"second", b"third", b"entry");
    let valid = RecoveryCursor {
        phase: RecoveryPhase::CompactReceipts,
        reap_leases: Some(valid_four),
        reap_colocated_shard: None,
        promote_delayed: Some(valid_three.clone()),
        cleanup_temp: Some(valid_three.clone()),
        compact_receipts: Some(valid_three.clone()),
        delete_receipts: Some(valid_three),
        hierarchy_retries: Vec::new(),
        hierarchy_retry_frontiers: Vec::new(),
        hierarchy_retry_overflow: Vec::new(),
    };
    assert!(cursor_is_valid(&valid));

    let mut invalid = Vec::new();
    for field in 0..4 {
        let mut cursor = valid.clone();
        let scan = cursor.reap_leases.as_mut().unwrap();
        match field {
            0 => scan.first.clear(),
            1 => scan.second.clear(),
            2 => scan.third.clear(),
            3 => scan.resume_after.clear(),
            _ => unreachable!(),
        }
        invalid.push(cursor);
    }
    for phase in 0..4 {
        for field in 0..3 {
            let mut cursor = valid.clone();
            let scan = match phase {
                0 => cursor.promote_delayed.as_mut().unwrap(),
                1 => cursor.cleanup_temp.as_mut().unwrap(),
                2 => cursor.compact_receipts.as_mut().unwrap(),
                3 => cursor.delete_receipts.as_mut().unwrap(),
                _ => unreachable!(),
            };
            match field {
                0 => scan.first.clear(),
                1 => scan.second.clear(),
                2 => scan.resume_after.clear(),
                _ => unreachable!(),
            }
            invalid.push(cursor);
        }
    }
    assert_eq!(invalid.len(), 16);
    for (index, cursor) in invalid.iter().enumerate() {
        assert!(!cursor_is_valid(cursor), "invalid cursor {index} accepted");
    }

    let retry = RecoveryHierarchyRetry {
        phase: RecoveryPhase::ReapLeases,
        kind: RecoveryHierarchyRetryKind::Open,
        components: vec![
            "00000000-0000-0000-0000-000000000000".into(),
            "0000000000000000".into(),
            "0000".into(),
        ],
    };
    let mut with_retry = valid.clone();
    with_retry.hierarchy_retries.push(retry.clone());
    assert!(cursor_is_valid(&with_retry));

    let boot = "00000000-0000-0000-0000-000000000000".to_string();
    let bucket = "0000000000000000".to_string();
    let shard = "0000".to_string();
    let mut all_shapes = valid.clone();
    all_shapes.hierarchy_retries = vec![
        RecoveryHierarchyRetry {
            phase: RecoveryPhase::ReapLeases,
            kind: RecoveryHierarchyRetryKind::Open,
            components: vec![boot.clone()],
        },
        RecoveryHierarchyRetry {
            phase: RecoveryPhase::ReapLeases,
            kind: RecoveryHierarchyRetryKind::Open,
            components: vec![boot.clone(), bucket.clone()],
        },
        RecoveryHierarchyRetry {
            phase: RecoveryPhase::ReapLeases,
            kind: RecoveryHierarchyRetryKind::Open,
            components: vec![boot.clone(), bucket.clone(), shard.clone()],
        },
        RecoveryHierarchyRetry {
            phase: RecoveryPhase::PromoteDelayed,
            kind: RecoveryHierarchyRetryKind::Open,
            components: vec![bucket.clone()],
        },
        RecoveryHierarchyRetry {
            phase: RecoveryPhase::PromoteDelayed,
            kind: RecoveryHierarchyRetryKind::Open,
            components: vec![bucket.clone(), shard.clone()],
        },
        RecoveryHierarchyRetry {
            phase: RecoveryPhase::CleanupTemp,
            kind: RecoveryHierarchyRetryKind::Open,
            components: vec![boot.clone()],
        },
        RecoveryHierarchyRetry {
            phase: RecoveryPhase::CleanupTemp,
            kind: RecoveryHierarchyRetryKind::Open,
            components: vec![boot, shard.clone()],
        },
        RecoveryHierarchyRetry {
            phase: RecoveryPhase::CompactReceipts,
            kind: RecoveryHierarchyRetryKind::Open,
            components: vec![bucket.clone()],
        },
        RecoveryHierarchyRetry {
            phase: RecoveryPhase::CompactReceipts,
            kind: RecoveryHierarchyRetryKind::Open,
            components: vec![bucket.clone(), shard.clone()],
        },
        RecoveryHierarchyRetry {
            phase: RecoveryPhase::DeleteReceipts,
            kind: RecoveryHierarchyRetryKind::Open,
            components: vec![bucket.clone()],
        },
        RecoveryHierarchyRetry {
            phase: RecoveryPhase::DeleteReceipts,
            kind: RecoveryHierarchyRetryKind::Open,
            components: vec![bucket, shard],
        },
    ];
    assert!(cursor_is_valid(&all_shapes));

    let mut duplicate = with_retry;
    duplicate.hierarchy_retries.push(retry);
    assert!(!cursor_is_valid(&duplicate));

    let mut wrong_depth = valid.clone();
    wrong_depth.hierarchy_retries.push(RecoveryHierarchyRetry {
        phase: RecoveryPhase::CompactReceipts,
        kind: RecoveryHierarchyRetryKind::Open,
        components: vec!["0000000000000000".into(), "0000".into(), "extra".into()],
    });
    assert!(!cursor_is_valid(&wrong_depth));

    let mut wrong_shape = valid;
    wrong_shape.hierarchy_retries.push(RecoveryHierarchyRetry {
        phase: RecoveryPhase::CleanupTemp,
        kind: RecoveryHierarchyRetryKind::Open,
        components: vec!["not-a-boot-id".into()],
    });
    assert!(!cursor_is_valid(&wrong_shape));

    let duplicate_overflow = RecoveryCursor {
        hierarchy_retry_overflow: vec![
            RecoveryPhase::CompactReceipts,
            RecoveryPhase::CompactReceipts,
        ],
        ..Default::default()
    };
    assert!(!cursor_is_valid(&duplicate_overflow));

    let ordered_overflow = RecoveryCursor {
        hierarchy_retry_overflow: vec![
            RecoveryPhase::ReapLeases,
            RecoveryPhase::PromoteDelayed,
            RecoveryPhase::CleanupTemp,
            RecoveryPhase::CompactReceipts,
            RecoveryPhase::DeleteReceipts,
        ],
        ..Default::default()
    };
    assert!(cursor_is_valid(&ordered_overflow));

    let frontier = RecoveryHierarchyRetry {
        phase: RecoveryPhase::CompactReceipts,
        kind: RecoveryHierarchyRetryKind::Enumerate,
        components: vec!["0000000000000000".into(), "0000".into()],
    };
    let ordered_frontiers = RecoveryCursor {
        hierarchy_retry_frontiers: vec![
            RecoveryHierarchyRetry {
                phase: RecoveryPhase::ReapLeases,
                kind: RecoveryHierarchyRetryKind::Open,
                components: vec!["00000000-0000-0000-0000-000000000000".into()],
            },
            frontier.clone(),
        ],
        ..Default::default()
    };
    assert!(cursor_is_valid(&ordered_frontiers));

    let duplicate_frontiers = RecoveryCursor {
        hierarchy_retry_frontiers: vec![frontier.clone(), frontier],
        ..Default::default()
    };
    assert!(!cursor_is_valid(&duplicate_frontiers));
}

#[test]
fn hierarchy_retry_ledger_is_bounded_sorted_and_deduplicated() {
    let (_tmp, mut queue) = create_test_queue();
    for bucket in (0..MAX_RECOVERY_HIERARCHY_RETRIES).rev() {
        let component = format!("{bucket:016x}");
        assert_eq!(
            queue.remember_hierarchy_retry(
                RecoveryPhase::CompactReceipts,
                RecoveryHierarchyRetryKind::Open,
                &[component.as_bytes()],
            ),
            RememberHierarchyRetry::Exact
        );
    }
    assert_eq!(
        queue.recovery_cursor.hierarchy_retries.len(),
        MAX_RECOVERY_HIERARCHY_RETRIES
    );
    assert!(queue
        .recovery_cursor
        .hierarchy_retries
        .windows(2)
        .all(|pair| pair[0] < pair[1]));
    assert_eq!(
        queue.remember_hierarchy_retry(
            RecoveryPhase::CompactReceipts,
            RecoveryHierarchyRetryKind::Open,
            &[b"0000000000000000"],
        ),
        RememberHierarchyRetry::Exact
    );
    assert_eq!(
        queue.recovery_cursor.hierarchy_retries.len(),
        MAX_RECOVERY_HIERARCHY_RETRIES
    );
    assert_eq!(
        queue.remember_hierarchy_retry(
            RecoveryPhase::CompactReceipts,
            RecoveryHierarchyRetryKind::Open,
            &[b"0000000000000040"],
        ),
        RememberHierarchyRetry::Overflow
    );
    assert_eq!(
        queue.recovery_cursor.hierarchy_retry_overflow,
        vec![RecoveryPhase::CompactReceipts]
    );

    queue.recovery_cursor.hierarchy_retries.clear();
    queue.recovery_cursor.hierarchy_retry_overflow.clear();
    for suffix in 0..MAX_RECOVERY_HIERARCHY_RETRIES {
        let boot = format!("00000000-0000-0000-0000-{suffix:012x}");
        assert_eq!(
            queue.remember_hierarchy_retry(
                RecoveryPhase::ReapLeases,
                RecoveryHierarchyRetryKind::Enumerate,
                &[boot.as_bytes(), b"0000000000000000", b"0000"],
            ),
            RememberHierarchyRetry::Exact
        );
    }
    queue.recovery_cursor.hierarchy_retry_overflow = vec![
        RecoveryPhase::ReapLeases,
        RecoveryPhase::PromoteDelayed,
        RecoveryPhase::CleanupTemp,
        RecoveryPhase::CompactReceipts,
        RecoveryPhase::DeleteReceipts,
    ];
    queue.recovery_cursor.hierarchy_retry_frontiers = vec![RecoveryHierarchyRetry {
        phase: RecoveryPhase::ReapLeases,
        kind: RecoveryHierarchyRetryKind::Enumerate,
        components: vec![
            "00000000-0000-0000-0000-00000000003f".into(),
            "0000000000000000".into(),
            "0000".into(),
        ],
    }];
    queue.persist_recovery_cursor().unwrap();
}

#[test]
fn enumeration_retry_requires_a_complete_accounted_read() {
    let (tmp, mut queue) = create_test_queue();
    std::fs::create_dir_all(tmp.path().join("receipts/0000000000000000/0000")).unwrap();
    assert_eq!(
        queue.remember_hierarchy_retry(
            RecoveryPhase::CompactReceipts,
            RecoveryHierarchyRetryKind::Enumerate,
            &[b"0000000000000000"],
        ),
        RememberHierarchyRetry::Exact
    );
    queue.recovery_cursor.compact_receipts = Some(ThreeLevelCursor::new(
        b"0000000000000000",
        b"0000",
        b"prior.rct",
    ));
    let receipts = fs::open_directory(queue.root_fd(), "receipts").unwrap();
    let budget = RecoveryScanBudget::default();
    let mut scan_stats = RecoveryScanStats::default();
    let mut scan = RecoveryScanContext {
        budget: &budget,
        stats: &mut scan_stats,
    };
    let mut stats = RecoveryStats::default();

    fs::fault::reset();
    fs::fault::inject_errno("open_directory", 2, libc::EIO);
    assert!(!retry_next_hierarchy_directory(
        &mut queue,
        RecoveryPhase::CompactReceipts,
        receipts.as_fd(),
        &mut scan,
        &mut stats,
        u64::MAX,
    ));
    fs::fault::reset();
    assert_eq!(queue.recovery_cursor.hierarchy_retries.len(), 1);
    assert!(queue.recovery_cursor.compact_receipts.is_some());
    assert_eq!(stats.scan_skips, 1);
    assert!(stats
        .errors
        .iter()
        .any(|error| error.operation == "hierarchy_retry_read"));

    let mut stats = RecoveryStats::default();
    assert!(!retry_next_hierarchy_directory(
        &mut queue,
        RecoveryPhase::CompactReceipts,
        receipts.as_fd(),
        &mut scan,
        &mut stats,
        u64::MAX,
    ));
    assert_eq!(scan.stats.entries_read, 1);
    assert!(queue.recovery_cursor.hierarchy_retries.is_empty());
    assert!(queue.recovery_cursor.compact_receipts.is_none());
}

#[test]
fn open_and_absent_retries_do_not_require_enumeration_budget() {
    let (tmp, mut queue) = create_test_queue();
    std::fs::create_dir_all(tmp.path().join("receipts/0000000000000000")).unwrap();
    assert_eq!(
        queue.remember_hierarchy_retry(
            RecoveryPhase::CompactReceipts,
            RecoveryHierarchyRetryKind::Open,
            &[b"0000000000000000"],
        ),
        RememberHierarchyRetry::Exact
    );
    assert_eq!(
        queue.remember_hierarchy_retry(
            RecoveryPhase::CompactReceipts,
            RecoveryHierarchyRetryKind::Enumerate,
            &[b"0000000000000001"],
        ),
        RememberHierarchyRetry::Exact
    );
    let receipts = fs::open_directory(queue.root_fd(), "receipts").unwrap();
    let budget = RecoveryScanBudget {
        max_directories_read: 0,
        max_entries_read: 0,
        max_name_bytes_read: 0,
    };
    let mut scan_stats = RecoveryScanStats::default();
    let mut scan = RecoveryScanContext {
        budget: &budget,
        stats: &mut scan_stats,
    };
    let mut stats = RecoveryStats::default();

    assert!(!retry_next_hierarchy_directory(
        &mut queue,
        RecoveryPhase::CompactReceipts,
        receipts.as_fd(),
        &mut scan,
        &mut stats,
        u64::MAX,
    ));
    assert!(!retry_next_hierarchy_directory(
        &mut queue,
        RecoveryPhase::CompactReceipts,
        receipts.as_fd(),
        &mut scan,
        &mut stats,
        u64::MAX,
    ));
    assert!(queue.recovery_cursor.hierarchy_retries.is_empty());
    assert_eq!(scan.stats.entries_read, 0);
    assert!(!stats.budget_exhausted);
}

#[test]
fn retry_replay_preserves_entry_and_clock_budget_failures() {
    let (tmp, mut queue) = create_test_queue();
    std::fs::create_dir_all(tmp.path().join("receipts/0000000000000000")).unwrap();
    assert_eq!(
        queue.remember_hierarchy_retry(
            RecoveryPhase::CompactReceipts,
            RecoveryHierarchyRetryKind::Open,
            &[b"0000000000000000"],
        ),
        RememberHierarchyRetry::Exact
    );
    let receipts = fs::open_directory(queue.root_fd(), "receipts").unwrap();
    let budget = RecoveryScanBudget::default();
    let mut scan_stats = RecoveryScanStats::default();
    let mut scan = RecoveryScanContext {
        budget: &budget,
        stats: &mut scan_stats,
    };
    let mut stats = RecoveryStats::default();

    assert!(retry_next_hierarchy_directory(
        &mut queue,
        RecoveryPhase::CompactReceipts,
        receipts.as_fd(),
        &mut scan,
        &mut stats,
        0,
    ));
    assert!(stats.budget_exhausted);
    assert_eq!(queue.recovery_cursor.hierarchy_retries.len(), 1);

    let mut stats = RecoveryStats::default();
    fs::fault::reset();
    fs::fault::inject("clock_monotonic_ns", 1);
    assert!(retry_next_hierarchy_directory(
        &mut queue,
        RecoveryPhase::CompactReceipts,
        receipts.as_fd(),
        &mut scan,
        &mut stats,
        u64::MAX,
    ));
    fs::fault::reset();
    assert!(stats.phase_blocked);
    assert!(stats.budget_exhausted);
    assert!(!Queue::has_recovery_budget(&stats));
    assert!(stats
        .errors
        .iter()
        .any(|error| error.operation == "clock_monotonic"));
    assert_eq!(queue.recovery_cursor.hierarchy_retries.len(), 1);

    let mut stats = RecoveryStats::default();
    assert!(!retry_next_hierarchy_directory(
        &mut queue,
        RecoveryPhase::CompactReceipts,
        receipts.as_fd(),
        &mut scan,
        &mut stats,
        u64::MAX,
    ));
    assert!(!stats.budget_exhausted);
    assert!(queue.recovery_cursor.hierarchy_retries.is_empty());
}

#[test]
fn retry_frontier_rotates_persistently_across_failures() {
    use std::os::unix::fs::symlink;

    let (tmp, mut queue) = create_test_queue();
    for bucket in 0..3 {
        symlink(
            tmp.path(),
            tmp.path().join(format!("receipts/{bucket:016x}")),
        )
        .unwrap();
        assert_eq!(
            queue.remember_hierarchy_retry(
                RecoveryPhase::CompactReceipts,
                RecoveryHierarchyRetryKind::Open,
                &[format!("{bucket:016x}").as_bytes()],
            ),
            RememberHierarchyRetry::Exact
        );
    }
    let receipts = fs::open_directory(queue.root_fd(), "receipts").unwrap();
    let budget = RecoveryScanBudget::default();
    let mut scan_stats = RecoveryScanStats::default();
    let mut scan = RecoveryScanContext {
        budget: &budget,
        stats: &mut scan_stats,
    };

    let mut stats = RecoveryStats::default();
    assert!(!retry_next_hierarchy_directory(
        &mut queue,
        RecoveryPhase::CompactReceipts,
        receipts.as_fd(),
        &mut scan,
        &mut stats,
        u64::MAX,
    ));
    assert_eq!(
        queue.recovery_cursor.hierarchy_retry_frontiers[0].components,
        vec!["0000000000000000"]
    );
    queue.persist_recovery_cursor().unwrap();
    drop(receipts);
    drop(queue);

    let mut reopened = Queue::open(
        tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    )
    .unwrap();
    let receipts = fs::open_directory(reopened.root_fd(), "receipts").unwrap();
    for expected in ["0000000000000001", "0000000000000002", "0000000000000000"] {
        let mut stats = RecoveryStats::default();
        assert!(!retry_next_hierarchy_directory(
            &mut reopened,
            RecoveryPhase::CompactReceipts,
            receipts.as_fd(),
            &mut scan,
            &mut stats,
            u64::MAX,
        ));
        assert_eq!(
            reopened.recovery_cursor.hierarchy_retry_frontiers[0].components,
            vec![expected]
        );
    }
}

#[test]
fn resolved_retry_updates_only_its_phase_frontier() {
    let (_tmp, mut queue) = create_test_queue();
    let receipts = fs::open_directory(queue.root_fd(), "receipts").unwrap();
    let budget = RecoveryScanBudget::default();
    let mut scan_stats = RecoveryScanStats::default();
    let mut scan = RecoveryScanContext {
        budget: &budget,
        stats: &mut scan_stats,
    };
    let reap_frontier = RecoveryHierarchyRetry {
        phase: RecoveryPhase::ReapLeases,
        kind: RecoveryHierarchyRetryKind::Open,
        components: vec!["00000000-0000-0000-0000-000000000000".into()],
    };
    let compact_frontier = RecoveryHierarchyRetry {
        phase: RecoveryPhase::CompactReceipts,
        kind: RecoveryHierarchyRetryKind::Open,
        components: vec!["000000000000000f".into()],
    };
    queue.recovery_cursor.hierarchy_retry_frontiers = vec![reap_frontier.clone(), compact_frontier];

    let mut stats = RecoveryStats::default();
    assert!(!queue.retry_one_hierarchy_directory(
        RecoveryPhase::CompactReceipts,
        None,
        receipts.as_fd(),
        &mut scan,
        &mut stats,
        u64::MAX,
    ));
    assert_eq!(
        queue.recovery_cursor.hierarchy_retry_frontiers,
        vec![reap_frontier.clone()]
    );

    let first = RecoveryHierarchyRetry {
        phase: RecoveryPhase::CompactReceipts,
        kind: RecoveryHierarchyRetryKind::Open,
        components: vec!["0000000000000000".into()],
    };
    let second = RecoveryHierarchyRetry {
        phase: RecoveryPhase::CompactReceipts,
        kind: RecoveryHierarchyRetryKind::Open,
        components: vec!["0000000000000001".into()],
    };
    queue.recovery_cursor.hierarchy_retries = vec![first.clone(), second.clone()];
    assert!(!queue.retry_one_hierarchy_directory(
        RecoveryPhase::CompactReceipts,
        Some(first.clone()),
        receipts.as_fd(),
        &mut scan,
        &mut stats,
        u64::MAX,
    ));
    assert_eq!(
        queue.recovery_cursor.hierarchy_retries,
        vec![second.clone()]
    );
    assert_eq!(
        queue.recovery_cursor.hierarchy_retry_frontiers,
        vec![reap_frontier.clone(), first]
    );

    let other_phase_retry = reap_frontier.clone();
    queue.recovery_cursor.hierarchy_retries = vec![other_phase_retry.clone(), second.clone()];
    assert!(!queue.retry_one_hierarchy_directory(
        RecoveryPhase::CompactReceipts,
        Some(second),
        receipts.as_fd(),
        &mut scan,
        &mut stats,
        u64::MAX,
    ));
    assert_eq!(
        queue.recovery_cursor.hierarchy_retries,
        vec![other_phase_retry]
    );
    assert_eq!(
        queue.recovery_cursor.hierarchy_retry_frontiers,
        vec![reap_frontier]
    );
}

#[test]
fn hierarchy_retry_overflow_rescans_without_starving_later_receipts() {
    use std::os::unix::fs::symlink;

    let (tmp, mut queue) = create_test_queue();
    enqueue_and_ack(&mut queue);
    enqueue_and_ack(&mut queue);
    for bucket in 0..=MAX_RECOVERY_HIERARCHY_RETRIES {
        symlink(
            tmp.path(),
            tmp.path().join(format!("receipts/{bucket:016x}")),
        )
        .unwrap();
    }
    let budget = WorkBudget {
        max_operations: 1,
        max_duration_ms: 5_000,
    };
    queue.recovery_cursor.phase = RecoveryPhase::CompactReceipts;
    queue.persist_recovery_cursor().unwrap();

    let first = queue.recover(&budget);
    assert_eq!(first.receipts_compacted, 1, "errors: {:?}", first.errors);
    assert_eq!(
        queue.recovery_cursor.hierarchy_retries.len(),
        MAX_RECOVERY_HIERARCHY_RETRIES
    );
    assert_eq!(
        queue.recovery_cursor.hierarchy_retry_overflow,
        vec![RecoveryPhase::CompactReceipts]
    );
    drop(queue);

    let mut reopened = Queue::open(
        tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    )
    .unwrap();
    let second = reopened.recover(&budget);
    assert_eq!(second.receipts_compacted, 1, "errors: {:?}", second.errors);
    assert!(second
        .errors
        .iter()
        .any(|error| error.operation == "hierarchy_retry_overflow"));
}

#[test]
fn recovery_cursor_without_retry_ledger_remains_compatible() {
    let mut value = serde_json::to_value(RecoveryCursor::default()).unwrap();
    value.as_object_mut().unwrap().remove("hierarchy_retries");
    value
        .as_object_mut()
        .unwrap()
        .remove("hierarchy_retry_frontiers");
    value
        .as_object_mut()
        .unwrap()
        .remove("hierarchy_retry_overflow");
    let decoded: RecoveryCursor = serde_json::from_value(value).unwrap();
    assert!(decoded.hierarchy_retries.is_empty());
    assert!(decoded.hierarchy_retry_frontiers.is_empty());
    assert!(decoded.hierarchy_retry_overflow.is_empty());

    let mut cursor = RecoveryCursor::default();
    cursor.hierarchy_retries.push(RecoveryHierarchyRetry {
        phase: RecoveryPhase::CompactReceipts,
        kind: RecoveryHierarchyRetryKind::Enumerate,
        components: vec!["0000000000000000".into()],
    });
    let mut value = serde_json::to_value(cursor).unwrap();
    value["hierarchy_retries"][0]
        .as_object_mut()
        .unwrap()
        .remove("kind");
    let decoded: RecoveryCursor = serde_json::from_value(value).unwrap();
    assert_eq!(
        decoded.hierarchy_retries[0].kind,
        RecoveryHierarchyRetryKind::Open
    );
}

#[test]
fn recovery_cursor_record_boundary_table() {
    assert_eq!(RECOVERY_CURSOR_MAX_BYTES, 16_384);
    assert_eq!(
        RECOVERY_CURSOR_OPEN_FLAGS,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW
    );
    assert_eq!(
        RECOVERY_LOCK_OPEN_FLAGS,
        libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW
    );
    for (size, expected) in [
        (0, false),
        (1, true),
        (RECOVERY_CURSOR_MAX_BYTES, true),
        (RECOVERY_CURSOR_MAX_BYTES + 1, false),
    ] {
        assert_eq!(cursor_record_size_is_valid(size), expected);
        assert_eq!(cursor_record_bytes_fit(size as usize), expected);
    }
    assert!(cursor_file_metadata_is_valid(libc::S_IFREG, 1));
    assert!(!cursor_file_metadata_is_valid(libc::S_IFDIR, 1));
    assert!(!cursor_file_metadata_is_valid(libc::S_IFREG, 2));
    assert!(!cursor_file_metadata_is_valid(libc::S_IFDIR, 2));

    let valid = RecoveryCursorRecord {
        schema: RECOVERY_CURSOR_SCHEMA.into(),
        version: RECOVERY_CURSOR_VERSION,
        queue_id: steadq_names::hex_encode(&[0; 16]),
        cursor: RecoveryCursor::default(),
    };
    assert!(cursor_record_version_is_supported(&valid));
    let mut wrong_schema = RecoveryCursorRecord {
        schema: "wrong".into(),
        ..valid
    };
    assert!(!cursor_record_version_is_supported(&wrong_schema));
    wrong_schema.schema = RECOVERY_CURSOR_SCHEMA.into();
    wrong_schema.version = RECOVERY_CURSOR_VERSION + 1;
    assert!(!cursor_record_version_is_supported(&wrong_schema));

    assert!(cursor_file_is_absent(&io::Error::from_raw_os_error(
        libc::ENOENT
    )));
    assert!(!cursor_file_is_absent(&io::Error::from_raw_os_error(
        libc::EIO
    )));
    assert!(recovery_lock_exists(&io::Error::from_raw_os_error(
        libc::EEXIST
    )));
    assert!(!recovery_lock_exists(&io::Error::from_raw_os_error(
        libc::EIO
    )));
}

#[test]
fn recovery_raw_name_diagnostic_preserves_non_utf8_bytes() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let tmp = TempDir::new().unwrap();
    // See fsck_preserves_non_ascii_name_bytes: skip on filesystems that
    // reject non-UTF-8 names outright.
    match std::fs::write(tmp.path().join(OsStr::from_bytes(b"probe-\x80")), b"") {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::EILSEQ) => return,
        Err(e) => panic!("probe write failed: {e}"),
    }
    std::fs::remove_file(tmp.path().join(OsStr::from_bytes(b"probe-\x80"))).unwrap();
    std::fs::write(tmp.path().join(OsStr::from_bytes(b"bad-\x80")), b"x").unwrap();
    let dir = std::fs::File::open(tmp.path()).unwrap();
    let mut stats = RecoveryScanStats::default();
    let entries = read_recovery_directory(
        dir.as_fd(),
        u64::MAX,
        &RecoveryScanBudget::default(),
        &mut stats,
    )
    .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(stats.entries_read, 1);
    assert_eq!(stats.name_bytes_read, 5);
    assert_eq!(raw_name_for_error(&entries[0]), "b\"bad-\\x80\"");
}

#[test]
fn recovery_directory_read_observes_expired_deadline_before_enumeration() {
    let tmp = TempDir::new().unwrap();
    std::fs::write(tmp.path().join("entry"), b"x").unwrap();
    let dir = std::fs::File::open(tmp.path()).unwrap();
    let mut stats = RecoveryScanStats::default();

    let error = read_recovery_directory(dir.as_fd(), 0, &RecoveryScanBudget::default(), &mut stats)
        .unwrap_err();

    assert!(matches!(error, RecoveryDirectoryError::BudgetExhausted));
    assert_eq!(stats.entries_read, 0);
    assert_eq!(stats.name_bytes_read, 0);
}

#[test]
fn recovery_directory_read_requires_budget_for_the_overflow_sentinel() {
    let tmp = TempDir::new().unwrap();
    std::fs::write(tmp.path().join("entry"), b"x").unwrap();
    let dir = std::fs::File::open(tmp.path()).unwrap();

    for budget in [
        RecoveryScanBudget {
            max_entries_read: MAX_RECOVERY_DIRECTORY_ENTRY_CHARGE - 1,
            ..RecoveryScanBudget::default()
        },
        RecoveryScanBudget {
            max_name_bytes_read: MAX_RECOVERY_DIRECTORY_NAME_BYTE_CHARGE - 1,
            ..RecoveryScanBudget::default()
        },
    ] {
        let mut stats = RecoveryScanStats::default();
        let error =
            read_recovery_directory(dir.as_fd(), u64::MAX, &budget, &mut stats).unwrap_err();

        assert!(matches!(error, RecoveryDirectoryError::BudgetExhausted));
        assert_eq!(stats.directories_read, 0);
        assert_eq!(stats.entries_read, 0);
        assert_eq!(stats.name_bytes_read, 0);
    }

    let exact_budget = RecoveryScanBudget {
        max_directories_read: 1,
        max_entries_read: MAX_RECOVERY_DIRECTORY_ENTRY_CHARGE,
        max_name_bytes_read: MAX_RECOVERY_DIRECTORY_NAME_BYTE_CHARGE,
    };
    let mut stats = RecoveryScanStats::default();
    let entries =
        read_recovery_directory(dir.as_fd(), u64::MAX, &exact_budget, &mut stats).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(stats.directories_read, 1);
    assert_eq!(stats.entries_read, 1);
    assert_eq!(stats.name_bytes_read, 5);
}

#[test]
fn recovery_directory_read_propagates_clock_failure() {
    let tmp = TempDir::new().unwrap();
    let dir = std::fs::File::open(tmp.path()).unwrap();
    let mut stats = RecoveryScanStats::default();
    fs::fault::reset();
    fs::fault::inject_errno("clock_monotonic_ns", 1, libc::EIO);

    let error = read_recovery_directory(
        dir.as_fd(),
        u64::MAX,
        &RecoveryScanBudget::default(),
        &mut stats,
    )
    .unwrap_err();

    fs::fault::reset();
    assert!(matches!(
        error,
        RecoveryDirectoryError::Clock(ref source)
            if source.raw_os_error() == Some(libc::EIO)
    ));
}

#[test]
fn recovery_cursor_load_distinguishes_absence_from_io_failure() {
    let (_tmp, queue) = create_test_queue();
    let absent = load_recovery_cursor(queue.root_fd(), queue.format.queue_id()).unwrap();
    assert_eq!(absent, RecoveryCursor::default());

    fs::fault::reset();
    fs::fault::inject_errno("openat", 1, libc::EIO);
    let error = load_recovery_cursor(queue.root_fd(), queue.format.queue_id()).unwrap_err();
    fs::fault::reset();
    assert!(matches!(
        error,
        Error::IoFailure(ref message) if message.contains("Input/output error")
    ));
}

#[test]
fn recovery_cursor_load_rejects_invalid_metadata_and_sizes() {
    let (directory_tmp, directory_queue) = create_test_queue();
    std::fs::create_dir(directory_tmp.path().join("control/recovery-cursor.json")).unwrap();
    assert!(matches!(
        load_recovery_cursor(
            directory_queue.root_fd(),
            directory_queue.format.queue_id()
        ),
        Err(Error::QueueCorrupt(ref message))
            if message == "recovery cursor is not a singly linked regular file"
    ));

    let (link_tmp, link_queue) = create_test_queue();
    let source = link_tmp.path().join("control/cursor-source");
    std::fs::write(
        &source,
        serde_json::to_vec(&valid_cursor_record(&link_queue)).unwrap(),
    )
    .unwrap();
    std::fs::hard_link(
        &source,
        link_tmp.path().join("control/recovery-cursor.json"),
    )
    .unwrap();
    assert!(matches!(
        load_recovery_cursor(link_queue.root_fd(), link_queue.format.queue_id()),
        Err(Error::QueueCorrupt(ref message))
            if message == "recovery cursor is not a singly linked regular file"
    ));

    for bytes in [Vec::new(), vec![0; RECOVERY_CURSOR_MAX_BYTES as usize + 1]] {
        let (tmp, queue) = create_test_queue();
        std::fs::write(tmp.path().join("control/recovery-cursor.json"), bytes).unwrap();
        assert!(matches!(
            load_recovery_cursor(queue.root_fd(), queue.format.queue_id()),
            Err(Error::QueueCorrupt(ref message))
                if message == "recovery cursor size is invalid"
        ));
    }
}

#[test]
fn recovery_cursor_load_rejects_schema_version_and_components() {
    let (schema_tmp, schema_queue) = create_test_queue();
    let mut wrong_schema = valid_cursor_record(&schema_queue);
    wrong_schema.schema = "wrong".into();
    std::fs::write(
        schema_tmp.path().join("control/recovery-cursor.json"),
        serde_json::to_vec(&wrong_schema).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        load_recovery_cursor(schema_queue.root_fd(), schema_queue.format.queue_id()),
        Err(Error::QueueCorrupt(ref message))
            if message == "recovery cursor schema or version is unsupported"
    ));

    let (version_tmp, version_queue) = create_test_queue();
    let mut wrong_version = valid_cursor_record(&version_queue);
    wrong_version.version += 1;
    std::fs::write(
        version_tmp.path().join("control/recovery-cursor.json"),
        serde_json::to_vec(&wrong_version).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        load_recovery_cursor(version_queue.root_fd(), version_queue.format.queue_id()),
        Err(Error::QueueCorrupt(ref message))
            if message == "recovery cursor schema or version is unsupported"
    ));

    let (component_tmp, component_queue) = create_test_queue();
    let mut invalid_component = valid_cursor_record(&component_queue);
    invalid_component.cursor.promote_delayed = Some(ThreeLevelCursor::new(b"", b"shard", b"entry"));
    std::fs::write(
        component_tmp.path().join("control/recovery-cursor.json"),
        serde_json::to_vec(&invalid_component).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        load_recovery_cursor(
            component_queue.root_fd(),
            component_queue.format.queue_id()
        ),
        Err(Error::QueueCorrupt(ref message))
            if message == "recovery cursor contains an invalid component"
    ));
}

#[test]
fn recovery_cursor_load_refuses_symlink() {
    use std::os::unix::fs::symlink;

    let (tmp, queue) = create_test_queue();
    let target = tmp.path().join("control/cursor-target");
    std::fs::write(
        &target,
        serde_json::to_vec(&valid_cursor_record(&queue)).unwrap(),
    )
    .unwrap();
    symlink(
        "cursor-target",
        tmp.path().join("control/recovery-cursor.json"),
    )
    .unwrap();

    assert!(matches!(
        load_recovery_cursor(queue.root_fd(), queue.format.queue_id()),
        Err(Error::IoFailure(_))
    ));
}

#[test]
fn recovery_cursor_persist_rejects_oversized_record() {
    let (_tmp, mut queue) = create_test_queue();
    queue.recovery_cursor.promote_delayed = Some(ThreeLevelCursor::new(
        &vec![b'x'; RECOVERY_CURSOR_MAX_BYTES as usize],
        b"shard",
        b"entry",
    ));
    assert!(matches!(
        queue.persist_recovery_cursor(),
        Err(Error::InvalidInput(ref message))
            if message == "recovery cursor exceeds maximum encoded size"
    ));
}

#[test]
fn recovery_cursor_publication_failures_reopen_old_or_complete_new_record() {
    for (fault_name, fault_count, expected_phase, expects_new) in [
        ("open_directory", 1, "phase=ControlOpen", false),
        ("get_random", 1, "phase=TempName", false),
        ("openat", 1, "phase=TempCreate", false),
        ("write_all", 1, "phase=TempWrite", false),
        ("fsync", 1, "phase=TempFsync", false),
        ("renameat", 1, "phase=Rename", false),
        ("fsync_dir_fd", 1, "phase=DestinationFsync", true),
        ("fsync", 2, "phase=DestinationFsync", true),
    ] {
        let (tmp, mut queue) = create_test_queue();
        let old_cursor = RecoveryCursor {
            phase: RecoveryPhase::PromoteDelayed,
            promote_delayed: Some(ThreeLevelCursor::new(
                b"0000000000000001",
                b"0001",
                b"old.sqj",
            )),
            ..Default::default()
        };
        queue.recovery_cursor = old_cursor.clone();
        queue.persist_recovery_cursor().unwrap();

        let new_cursor = RecoveryCursor {
            phase: RecoveryPhase::DeleteReceipts,
            delete_receipts: Some(ThreeLevelCursor::new(
                b"0000000000000002",
                b"0002",
                b"new.rct",
            )),
            ..Default::default()
        };
        queue.recovery_cursor = new_cursor.clone();
        fs::fault::reset();
        fs::fault::inject_errno(fault_name, fault_count, libc::EIO);
        let error = queue.persist_recovery_cursor().unwrap_err();
        assert!(matches!(error, Error::IoFailure(_)));
        assert!(
            error.to_string().contains(expected_phase),
            "fault={fault_name} count={fault_count}: {error}"
        );
        if expects_new {
            assert!(
                !error.to_string().contains("stale recovery cursor"),
                "fault={fault_name} count={fault_count}: {error}"
            );
        }
        fs::fault::reset();
        drop(queue);

        let reopened = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            reopened.recovery_cursor,
            if expects_new { new_cursor } else { old_cursor },
            "fault={fault_name} count={fault_count}"
        );
        let stale_temps = std::fs::read_dir(tmp.path().join("control"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.as_encoded_bytes().starts_with(b".recovery-cursor."))
            .count();
        assert_eq!(stale_temps, 0, "fault={fault_name} count={fault_count}");
    }
}

#[test]
fn recovery_cursor_cleanup_failure_classifies_stale_temporary_file() {
    for (cleanup_fault, expected_diagnosis, expected_live_temps) in [
        (
            "unlinkat",
            "stale recovery cursor temporary file requires later cleanup",
            1,
        ),
        (
            "fsync_dir_fd",
            "cleanup durability is unknown for stale recovery cursor temporary file",
            0,
        ),
    ] {
        let (tmp, mut queue) = create_test_queue();
        let old_cursor = RecoveryCursor {
            phase: RecoveryPhase::PromoteDelayed,
            ..Default::default()
        };
        queue.recovery_cursor = old_cursor.clone();
        queue.persist_recovery_cursor().unwrap();
        queue.recovery_cursor.phase = RecoveryPhase::DeleteReceipts;

        fs::fault::reset();
        fs::fault::inject_errno("write_all", 1, libc::EIO);
        fs::fault::inject_errno(cleanup_fault, 1, libc::EIO);
        let error = queue.persist_recovery_cursor().unwrap_err();
        fs::fault::reset();
        let Error::IoFailure(message) = error else {
            panic!("unexpected cursor publication error: {error:?}");
        };
        assert!(
            message.contains(expected_diagnosis),
            "cleanup_fault={cleanup_fault}: {message}"
        );
        assert!(message.contains("control/.recovery-cursor."));
        drop(queue);

        let reopened = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(reopened.recovery_cursor, old_cursor);
        let stale_temps = std::fs::read_dir(tmp.path().join("control"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.as_encoded_bytes().starts_with(b".recovery-cursor."))
            .count();
        assert_eq!(
            stale_temps, expected_live_temps,
            "cleanup_fault={cleanup_fault}"
        );
    }
}

#[test]
fn recovery_cursor_failure_replays_prior_progress_without_skipping_work() {
    let (tmp, mut queue) = create_test_queue_with_shards(2);
    let not_before = queue
        .authenticated_wall_floor()
        .unwrap()
        .unix_ns()
        .checked_add(queue.format.delayed_bucket_width_ns() * 4)
        .unwrap();
    let ticket = enqueue_for_shard(&mut queue, &tmp, 0, Some(not_before), b"cursor-replay");
    let delayed_parts = ticket
        .expected_relative_path
        .split('/')
        .map(str::as_bytes)
        .collect::<Vec<_>>();
    assert_eq!(delayed_parts.len(), 4);
    let delayed_bucket =
        steadq_names::bucket_from_hex(std::str::from_utf8(delayed_parts[1]).unwrap()).unwrap();
    write_wall_watermark(&tmp, delayed_bucket);

    let old_cursor = RecoveryCursor {
        phase: RecoveryPhase::PromoteDelayed,
        ..Default::default()
    };
    queue.recovery_cursor = old_cursor.clone();
    queue.persist_recovery_cursor().unwrap();
    queue.recovery_cursor.promote_delayed = Some(ThreeLevelCursor::new(
        delayed_parts[1],
        delayed_parts[2],
        delayed_parts[3],
    ));

    fs::fault::reset();
    fs::fault::inject_errno("write_all", 1, libc::EIO);
    assert!(matches!(
        queue.persist_recovery_cursor(),
        Err(Error::IoFailure(_))
    ));
    fs::fault::reset();
    drop(queue);

    let mut reopened = Queue::open(
        tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(reopened.recovery_cursor, old_cursor);
    let report = reopened.recover(&WorkBudget {
        max_operations: 1,
        max_duration_ms: 30_000,
    });
    assert_eq!(report.delayed_promoted, 1);
    assert!(tmp.path().join("ready").exists());
    assert!(!tmp.path().join(&ticket.expected_relative_path).exists());
}

#[test]
fn recovery_lock_creation_error_is_not_treated_as_contention() {
    let (_tmp, queue) = create_test_queue();
    fs::fault::reset();
    fs::fault::inject_errno("openat", 1, libc::EIO);
    let error = queue.acquire_recovery_lock().unwrap_err();
    fs::fault::reset();
    assert!(matches!(
        error,
        Error::IoFailure(ref message) if message.contains("Input/output error")
    ));
}

#[test]
fn recovery_lock_refuses_symlink() {
    use std::os::unix::fs::symlink;

    let (tmp, queue) = create_test_queue();
    let target = tmp.path().join("lock-target");
    std::fs::write(&target, b"target").unwrap();
    let lock_path = tmp.path().join("control/recovery.lock");
    std::fs::remove_file(&lock_path).unwrap();
    symlink(&target, lock_path).unwrap();

    assert!(matches!(
        queue.acquire_recovery_lock(),
        Err(Error::IoFailure(_))
    ));
}

#[test]
fn recovery_cursor_persists_exact_budget_progress_across_reopen() {
    let (tmp, mut queue) = create_test_queue();
    enqueue_and_ack(&mut queue);
    enqueue_and_ack(&mut queue);
    let receipt_root = tmp.path().join("receipts");
    let mut original_receipts = Vec::new();
    find_files(&receipt_root, "rct", &mut original_receipts);
    original_receipts.sort_by_key(|path| path.strip_prefix(&receipt_root).unwrap().to_path_buf());
    let first_parts = original_receipts[0]
        .strip_prefix(&receipt_root)
        .unwrap()
        .components()
        .map(|component| component.as_os_str().to_str().unwrap())
        .collect::<Vec<_>>();
    let budget = WorkBudget {
        max_operations: 1,
        max_duration_ms: 5_000,
    };

    let first = queue.recover(&budget);
    assert_eq!(first.receipts_compacted, 1, "errors: {:?}", first.errors);
    assert!(first.budget_exhausted);
    assert_eq!(
        queue.recovery_cursor.compact_receipts,
        Some(ThreeLevelCursor::new(
            first_parts[0].as_bytes(),
            first_parts[1].as_bytes(),
            first_parts[2].as_bytes()
        ))
    );
    assert!(tmp.path().join("control/recovery-cursor.json").exists());
    drop(queue);

    let mut reopened = Queue::open(
        tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(reopened.recovery_cursor.compact_receipts.is_some());
    let second = reopened.recover(&budget);
    assert_eq!(second.receipts_compacted, 1, "errors: {:?}", second.errors);
    drop(reopened);

    let mut receipts = Vec::new();
    find_files(&tmp.path().join("receipts"), "rct", &mut receipts);
    assert_eq!(receipts.len(), 2);
    assert!(receipts
        .iter()
        .all(|path| std::fs::metadata(path).unwrap().len() == 128));
}

#[test]
fn persistent_malformed_receipt_does_not_starve_valid_receipt() {
    let (tmp, mut queue) = create_test_queue();
    enqueue_and_ack(&mut queue);
    let receipt = find_file(&tmp.path().join("receipts"), "rct").unwrap();
    let malformed = receipt.parent().unwrap().join("000-malformed.rct");
    std::fs::write(&malformed, b"malformed").unwrap();
    let budget = WorkBudget {
        max_operations: 1,
        max_duration_ms: 5_000,
    };

    let first = queue.recover(&budget);
    assert_eq!(first.receipts_compacted, 1, "errors: {:?}", first.errors);
    assert!(first
        .errors
        .iter()
        .any(|error| error.operation == "receipt_compact_invalid"));
    assert!(queue.recovery_cursor.compact_receipts.is_none());
    drop(queue);

    let mut reopened = Queue::open(
        tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    )
    .unwrap();
    let second = reopened.recover(&budget);

    assert_eq!(second.receipts_compacted, 0, "errors: {:?}", second.errors);
    assert_eq!(std::fs::metadata(receipt).unwrap().len(), 128);
    assert!(malformed.exists());
}

#[test]
fn busy_receipt_does_not_pin_recovery_cursor() {
    let (tmp, mut queue) = create_test_queue();
    enqueue_and_ack(&mut queue);
    enqueue_and_ack(&mut queue);
    let receipt_root = tmp.path().join("receipts");
    let mut receipts = Vec::new();
    find_files(&receipt_root, "rct", &mut receipts);
    receipts.sort_by_key(|path| path.strip_prefix(&receipt_root).unwrap().to_path_buf());
    let held = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&receipts[0])
        .unwrap();
    let held_original_len = std::fs::metadata(&receipts[0]).unwrap().len();
    assert!(fs::try_ofd_write_lock(held.as_fd()).unwrap());
    let budget = WorkBudget {
        max_operations: 1,
        max_duration_ms: 5_000,
    };

    let first = queue.recover(&budget);
    assert_eq!(first.receipts_compacted, 1, "errors: {:?}", first.errors);
    drop(queue);
    let mut reopened = Queue::open(
        tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    )
    .unwrap();
    let second = reopened.recover(&budget);

    assert_eq!(second.receipts_compacted, 0, "errors: {:?}", second.errors);
    assert_eq!(
        std::fs::metadata(&receipts[0]).unwrap().len(),
        held_original_len
    );
    assert_eq!(std::fs::metadata(&receipts[1]).unwrap().len(), 128);
}

#[test]
fn recovery_cursor_rejects_foreign_queue_identity() {
    let (tmp, mut queue) = create_test_queue();
    queue.recovery_cursor.compact_receipts =
        Some(ThreeLevelCursor::new(b"0001", b"0002", b"entry.rct"));
    queue.persist_recovery_cursor().unwrap();
    drop(queue);
    let path = tmp.path().join("control/recovery-cursor.json");
    let mut record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    record["queue_id"] = serde_json::Value::String(steadq_names::hex_encode(&[0xff; 16]));
    std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();

    let error = Queue::open(
        tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    )
    .err()
    .expect("foreign cursor must reject queue open");
    assert!(matches!(
        error,
        Error::QueueCorrupt(ref message)
            if message == "recovery cursor belongs to another queue"
    ));
}

#[test]
fn concurrent_recovery_pass_is_rejected_by_lock() {
    let (_tmp, first) = create_test_queue();
    let mut second = Queue::open(
        _tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    )
    .unwrap();
    let _held = first.acquire_recovery_lock().unwrap();

    let stats = second.recover(&WorkBudget::default());

    assert_eq!(stats.errors.len(), 1);
    assert_eq!(stats.errors[0].operation, "recovery_lock");
    assert_eq!(stats.errors[0].error, Error::MaintenanceBusy.to_string());
}

#[test]
fn recovery_reaps_expired_lease() {
    let (_tmp, mut queue) = create_test_queue();

    // Enqueue and lease
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    });
    let _lease = match queue.lease(0, 1_000_000_000) {
        // 1s lease
        LeaseOutcome::Leased(l) => l,
        _ => panic!("lease failed"),
    };

    // Cannot rewrite the deadline in the filename; instead let a future
    // boottime reap it. Sleep briefly so the lease expires.
    std::thread::sleep(std::time::Duration::from_secs(2));

    let stats = queue.recover(&WorkBudget::default());
    // Reaped to ready (attempt < max) or dead
    assert!(stats.leases_reaped >= 1 || stats.leases_to_dead >= 1);

    let result = queue.lease(0, 30_000_000_000);
    assert!(matches!(result, LeaseOutcome::Leased(_)));
}

#[test]
fn recovery_quarantines_malformed_leased_filename() {
    let (tmp, mut queue) = create_test_queue();
    let dir = tmp
        .path()
        .join("leased")
        .join(queue.boot_id())
        .join("0000000000000000")
        .join("0000");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("not-a-leased-name.sqj"), b"garbage").unwrap();

    let stats = reap_expired_with_budget(&mut queue, &WorkBudget::default());
    assert!(
        stats
            .quarantined
            .iter()
            .any(|entry| entry.relative_path.contains("not-a-leased-name")),
        "errors: {:?}",
        stats.errors
    );
    assert!(queue
        .list_quarantine()
        .iter()
        .any(|entry| entry.reason == crate::QuarantineReason::FilenameParseFailed as u16));
    assert!(!dir.join("not-a-leased-name.sqj").exists());
}

#[test]
fn colocated_ready_leases_respect_operation_budget() {
    let (_tmp, mut queue) = create_test_queue_with_shards(1);
    let _ = lease_recovery_job(&mut queue, 3);
    let _ = lease_recovery_job(&mut queue, 3);
    let first = reap_expired_with_budget(
        &mut queue,
        &WorkBudget {
            max_operations: 1,
            max_duration_ms: 5_000,
        },
    );
    assert_eq!(first.operations_attempted, 1);
    assert_eq!(first.leases_reaped, 1, "errors: {:?}", first.errors);
    assert!(first.budget_exhausted);
    let second = reap_expired_with_budget(
        &mut queue,
        &WorkBudget {
            max_operations: 1,
            max_duration_ms: 5_000,
        },
    );
    assert_eq!(second.operations_attempted, 1);
    assert_eq!(second.leases_reaped, 1, "errors: {:?}", second.errors);
}

#[test]
fn previous_boot_colocated_lease_is_reaped_before_deadline() {
    let (_tmp, mut queue) = create_test_queue();
    let _ = lease_recovery_job(&mut queue, 3);
    queue.boot_id = "00000000-0000-0000-0000-000000000099".into();
    let scan_budget = RecoveryScanBudget::default();
    let mut scan_stats = RecoveryScanStats::default();
    let mut scan = RecoveryScanContext {
        budget: &scan_budget,
        stats: &mut scan_stats,
    };
    let mut stats = RecoveryStats::default();
    queue.reap_expired_leases(
        0,
        Some(queue.authenticated_wall_floor().unwrap()),
        &WorkBudget::default(),
        &mut scan,
        &mut stats,
        u64::MAX,
    );
    assert_eq!(stats.leases_reaped, 1, "errors: {:?}", stats.errors);
}

#[test]
fn colocated_ready_shard_open_failure_counts_scan_skip() {
    let (tmp, mut queue) = create_test_queue_with_shards(1);
    std::fs::remove_dir_all(tmp.path().join("ready/0000")).unwrap();
    std::fs::write(tmp.path().join("ready/0000"), b"not a directory").unwrap();
    let stats = reap_expired_with_budget(&mut queue, &WorkBudget::default());
    assert_eq!(stats.scan_skips, 1);
}

#[test]
fn colocated_ready_read_budget_counts_scan_skip() {
    let (_tmp, mut queue) = create_test_queue();
    let scan_budget = RecoveryScanBudget {
        max_directories_read: 1,
        max_entries_read: u64::MAX,
        max_name_bytes_read: u64::MAX,
    };
    let mut scan_stats = RecoveryScanStats::default();
    let mut scan = RecoveryScanContext {
        budget: &scan_budget,
        stats: &mut scan_stats,
    };
    let mut stats = RecoveryStats::default();
    queue.reap_expired_leases(
        u64::MAX,
        Some(queue.authenticated_wall_floor().unwrap()),
        &WorkBudget::default(),
        &mut scan,
        &mut stats,
        u64::MAX,
    );
    assert_eq!(stats.scan_skips, 1);
}

#[test]
fn colocated_current_boot_skips_future_deadline() {
    fs::fault::set_clock_boottime_ns(1_000_000_000);
    let (_tmp, mut queue) = create_test_queue();
    let _ = lease_recovery_job(&mut queue, 3);
    let scan_budget = RecoveryScanBudget::default();
    let mut scan_stats = RecoveryScanStats::default();
    let mut scan = RecoveryScanContext {
        budget: &scan_budget,
        stats: &mut scan_stats,
    };
    let mut stats = RecoveryStats::default();
    queue.reap_expired_leases(
        1_000_000_000,
        Some(queue.authenticated_wall_floor().unwrap()),
        &WorkBudget::default(),
        &mut scan,
        &mut stats,
        u64::MAX,
    );
    fs::fault::reset();
    assert_eq!(stats.leases_reaped, 0, "errors: {:?}", stats.errors);
}

#[test]
fn colocated_current_boot_reaps_at_deadline() {
    fs::fault::set_clock_boottime_ns(1_000_000_000);
    let (_tmp, mut queue) = create_test_queue();
    let lease = lease_recovery_job(&mut queue, 3);
    let scan_budget = RecoveryScanBudget::default();
    let mut scan_stats = RecoveryScanStats::default();
    let mut scan = RecoveryScanContext {
        budget: &scan_budget,
        stats: &mut scan_stats,
    };
    let mut stats = RecoveryStats::default();
    queue.reap_expired_leases(
        lease.expires_boottime_ns,
        Some(queue.authenticated_wall_floor().unwrap()),
        &WorkBudget::default(),
        &mut scan,
        &mut stats,
        u64::MAX,
    );
    fs::fault::reset();
    assert_eq!(stats.leases_reaped, 1, "errors: {:?}", stats.errors);
}

#[test]
fn recovery_empty_queue() {
    let (_tmp, mut queue) = create_test_queue();
    let report =
        queue.recover_with_scan_budget(&WorkBudget::default(), &RecoveryScanBudget::default());
    assert_eq!(report.stats.operations_attempted, 0);
    assert_eq!(
        report.scan.directories_read,
        5 + u64::from(queue.format.shard_count())
    );
    assert_eq!(report.scan.entries_read, 0);
    assert_eq!(report.scan.name_bytes_read, 0);

    let stats = queue.recover(&WorkBudget::default());
    assert_eq!(stats.operations_attempted, 0);
    assert!(!stats.budget_exhausted);
}

#[test]
fn reap_to_dead_rejects_generation_overflow() {
    let (_tmp, queue) = create_test_queue();
    let common = steadq_names::CommonFields {
        job_id: [0xAB; 16],
        generation: u64::MAX,
        attempt: 0,
        maximum_attempts: 3,
    };
    let res = queue.reap_to_dead(
        queue.root_fd(),
        "dummy",
        &common,
        crate::errors::DeadReason::AttemptsExhausted,
        queue.authenticated_wall_floor().unwrap(),
    );
    assert!(res.is_err(), "generation overflow must be Err, got {res:?}");
}

#[test]
fn recovery_move_failure_preserves_category_and_phase() {
    for (failure, expected_operation, expected_detail) in [
        (
            MoveFailure::NotCommitted {
                phase: MovePhase::Rename,
                source: std::io::Error::other("rename failed"),
            },
            "move_not_committed",
            "phase=Rename",
        ),
        (
            MoveFailure::OutcomeUnknown {
                phase: MovePhase::DestFsync,
                source: std::io::Error::other("sync failed"),
            },
            "move_outcome_unknown",
            "phase=DestFsync",
        ),
        (
            MoveFailure::AlreadyExists,
            "move_collision",
            "destination already exists",
        ),
        (
            MoveFailure::SourceMissing,
            "move_source_missing",
            "source is missing",
        ),
    ] {
        let mut stats = RecoveryStats::default();
        Queue::record_move_failure(&mut stats, "move", "source/path", failure);
        assert_eq!(stats.errors.len(), 1);
        assert_eq!(stats.errors[0].operation, expected_operation);
        assert_eq!(stats.errors[0].relative_path, "source/path");
        assert!(stats.errors[0].error.contains(expected_detail));
    }
}

#[test]
fn reap_to_ready_uses_phase_aware_move_executor() {
    for (fault, count, phase, outcome_unknown) in [
        ("renameat2_noreplace", 1, MovePhase::Rename, false),
        ("fsync_dir_fd", 1, MovePhase::DestFsync, true),
    ] {
        let (_tmp, mut queue) = create_test_queue();
        let lease = lease_recovery_job(&mut queue, 3);
        let common = lease_common(&lease);
        let parts = lease_path_parts(&lease);
        fs::fault::reset();
        fs::fault::inject_errno(fault, count, libc::EIO);
        let shard_fd = open_relative(queue.root_fd(), &format!("ready/{}", parts[1])).unwrap();
        let result = queue.reap_colocated_to_ready(shard_fd.as_fd(), parts[2], &common);
        fs::fault::reset();
        assert_injected_move_phase(result, phase, outcome_unknown);
    }
}

#[test]
fn reap_to_dead_uses_phase_aware_move_executor() {
    for (fault, count, phase, outcome_unknown) in [
        ("renameat2_noreplace", 1, MovePhase::Rename, false),
        ("fsync_dir_fd", 1, MovePhase::DestFsync, true),
        ("fsync_dir_fd", 2, MovePhase::SourceFsync, true),
    ] {
        let (_tmp, mut queue) = create_test_queue();
        let lease = lease_recovery_job(&mut queue, 1);
        let common = lease_common(&lease);
        let parts = lease_path_parts(&lease);
        let wall_floor = queue.authenticated_wall_floor().unwrap();
        let terminal_bucket = steadq_math::bucket_number(
            wall_floor.unix_ns(),
            queue.format.terminal_bucket_width_ns(),
        )
        .unwrap();
        queue
            .ensure_dir(&format!(
                "dead/{}/{}",
                steadq_names::bucket_hex(terminal_bucket),
                parts[1]
            ))
            .unwrap();
        fs::fault::reset();
        fs::fault::inject_errno(fault, count, libc::EIO);
        let shard_fd = open_relative(queue.root_fd(), &format!("ready/{}", parts[1])).unwrap();
        let result = queue.reap_colocated_to_dead(
            shard_fd.as_fd(),
            parts[2],
            &common,
            DeadReason::AttemptsExhausted,
            wall_floor,
        );
        fs::fault::reset();
        assert_injected_move_phase(result, phase, outcome_unknown);
    }
}

#[test]
fn delayed_promotion_uses_phase_aware_move_executor() {
    for (fault, count, phase, outcome_unknown) in [
        ("renameat2_noreplace", 1, MovePhase::Rename, false),
        ("fsync_dir_fd", 1, MovePhase::DestFsync, true),
        ("fsync_dir_fd", 2, MovePhase::SourceFsync, true),
    ] {
        let (tmp, mut queue) = create_test_queue();
        let not_before = queue
            .authenticated_wall_floor()
            .unwrap()
            .unix_ns()
            .checked_add(queue.format.delayed_bucket_width_ns())
            .unwrap();
        let ticket = match queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".into(),
            initial_not_before: Some(not_before),
            payload: b"delayed move".to_vec(),
            ..Default::default()
        }) {
            EnqueueOutcome::Committed(ticket) => ticket,
            outcome => panic!("enqueue failed: {outcome:?}"),
        };
        let parts = ticket.expected_relative_path.split('/').collect::<Vec<_>>();
        assert_eq!(parts.len(), 4);
        let parsed = steadq_names::parse_delayed(parts[3]).unwrap();
        assert!(tmp.path().join(&ticket.expected_relative_path).exists());
        fs::fault::reset();
        fs::fault::inject_errno(fault, count, libc::EIO);
        let shard_fd = open_relative(
            queue.root_fd(),
            &format!("delayed/{}/{}", parts[1], parts[2]),
        )
        .unwrap();
        let result = queue.promote_to_ready(shard_fd.as_fd(), parts[2], parts[3], &parsed.common);
        fs::fault::reset();
        assert_injected_move_phase(result, phase, outcome_unknown);
    }
}

#[test]
fn reap_to_ready_records_executor_failure_without_counting_commit() {
    for (fault, count, phase, outcome_unknown) in [
        ("renameat2_noreplace", 1, MovePhase::Rename, false),
        ("fsync_dir_fd", 1, MovePhase::DestFsync, true),
    ] {
        let (tmp, mut queue) = create_test_queue();
        let lease = lease_recovery_job(&mut queue, 3);
        let parts = lease_path_parts(&lease);
        let common = lease_common(&lease);
        let source = tmp.path().join(&lease.exact_source_path);
        let destination = tmp
            .path()
            .join(ready_destination(&queue, parts[1], &common));
        fs::fault::reset();
        fs::fault::inject_errno(fault, count, libc::EIO);
        let stats = reap_expired_with_budget(&mut queue, &WorkBudget::default());
        fs::fault::reset();
        assert_eq!(stats.leases_reaped, 0);
        assert_recorded_move_failure(&stats, "reap_to_ready", phase, outcome_unknown);
        assert_eq!(source.exists(), !outcome_unknown);
        assert_eq!(destination.exists(), outcome_unknown);
        if outcome_unknown {
            assert!(queue
                .inspect(&lease.job_id)
                .iter()
                .any(|snapshot| snapshot.state == "ready"));
        }
        queue.persist_recovery_cursor().unwrap();
        drop(queue);
        let mut reopened = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        let replay = reap_expired_with_budget(&mut reopened, &WorkBudget::default());
        assert_eq!(replay.leases_reaped, u32::from(!outcome_unknown));
        assert!(!source.exists());
        assert!(destination.exists());
    }
}

#[test]
fn reap_to_dead_records_executor_failure_without_counting_commit() {
    for (fault, count, phase, outcome_unknown) in [
        ("renameat2_noreplace", 1, MovePhase::Rename, false),
        ("fsync_dir_fd", 1, MovePhase::DestFsync, true),
        ("fsync_dir_fd", 2, MovePhase::SourceFsync, true),
    ] {
        let (tmp, mut queue) = create_test_queue();
        let lease = lease_recovery_job(&mut queue, 1);
        let shard = lease.exact_source_path.split('/').nth(1).unwrap();
        let common = lease_common(&lease);
        let wall_floor = queue.authenticated_wall_floor().unwrap();
        let source = tmp.path().join(&lease.exact_source_path);
        let destination = tmp
            .path()
            .join(dead_destination(&queue, shard, &common, wall_floor));
        let terminal_bucket = steadq_math::bucket_number(
            wall_floor.unix_ns(),
            queue.format.terminal_bucket_width_ns(),
        )
        .unwrap();
        queue
            .ensure_dir(&format!(
                "dead/{}/{shard}",
                steadq_names::bucket_hex(terminal_bucket)
            ))
            .unwrap();
        fs::fault::reset();
        fs::fault::inject_errno(fault, count, libc::EIO);
        let stats = reap_expired_with_budget(&mut queue, &WorkBudget::default());
        fs::fault::reset();
        assert_eq!(stats.leases_to_dead, 0);
        assert_recorded_move_failure(&stats, "reap_to_dead", phase, outcome_unknown);
        assert_eq!(source.exists(), !outcome_unknown);
        assert_eq!(destination.exists(), outcome_unknown);
        if outcome_unknown {
            assert!(queue
                .inspect(&lease.job_id)
                .iter()
                .any(|snapshot| snapshot.state == "dead"));
        }
        queue.persist_recovery_cursor().unwrap();
        drop(queue);
        let mut reopened = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        let replay = reap_expired_with_budget(&mut reopened, &WorkBudget::default());
        assert_eq!(replay.leases_to_dead, u32::from(!outcome_unknown));
        assert!(!source.exists());
        assert!(destination.exists());
    }
}

#[test]
fn delayed_promotion_records_executor_failure_without_counting_commit() {
    for (fault, count, phase, outcome_unknown) in [
        ("renameat2_noreplace", 1, MovePhase::Rename, false),
        ("fsync_dir_fd", 1, MovePhase::DestFsync, true),
        ("fsync_dir_fd", 2, MovePhase::SourceFsync, true),
    ] {
        let (tmp, mut queue) = create_test_queue();
        let not_before = queue
            .authenticated_wall_floor()
            .unwrap()
            .unix_ns()
            .checked_add(queue.format.delayed_bucket_width_ns())
            .unwrap();
        let ticket = match queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".into(),
            initial_not_before: Some(not_before),
            payload: b"delayed recovery".to_vec(),
            ..Default::default()
        }) {
            EnqueueOutcome::Committed(ticket) => ticket,
            outcome => panic!("enqueue failed: {outcome:?}"),
        };
        let delayed_bucket = ticket
            .expected_relative_path
            .split('/')
            .nth(1)
            .and_then(steadq_names::bucket_from_hex)
            .unwrap();
        let parts = ticket.expected_relative_path.split('/').collect::<Vec<_>>();
        let parsed = steadq_names::parse_delayed(parts[3]).unwrap();
        let source = tmp.path().join(&ticket.expected_relative_path);
        let destination = tmp
            .path()
            .join(ready_destination(&queue, parts[2], &parsed.common));
        write_wall_watermark(&tmp, delayed_bucket);
        let wall_floor = queue.authenticated_wall_floor().unwrap();
        fs::fault::reset();
        fs::fault::inject_errno(fault, count, libc::EIO);
        let stats = promote_eligible_with_budget(&mut queue, wall_floor);
        fs::fault::reset();
        assert_eq!(stats.delayed_promoted, 0);
        assert_recorded_move_failure(&stats, "promote_delayed", phase, outcome_unknown);
        assert_eq!(source.exists(), !outcome_unknown);
        assert_eq!(destination.exists(), outcome_unknown);
        if outcome_unknown {
            assert!(queue
                .inspect(&ticket.job_id)
                .iter()
                .any(|snapshot| snapshot.state == "ready"));
        }
        queue.persist_recovery_cursor().unwrap();
        drop(queue);
        let mut reopened = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        let replay_floor = reopened.authenticated_wall_floor().unwrap();
        let replay = promote_eligible_with_budget(&mut reopened, replay_floor);
        assert_eq!(replay.delayed_promoted, u32::from(!outcome_unknown));
        assert!(!source.exists());
        assert!(destination.exists());
    }
}

#[test]
fn reap_to_ready_scanner_handles_collision_and_missing_source() {
    for collision in [true, false] {
        let (tmp, mut queue) = create_test_queue();
        let lease = lease_recovery_job(&mut queue, 3);
        let parts = lease_path_parts(&lease);
        let source = tmp.path().join(&lease.exact_source_path);
        let destination =
            tmp.path()
                .join(ready_destination(&queue, parts[1], &lease_common(&lease)));
        if collision {
            std::fs::copy(&source, &destination).unwrap();
        } else {
            fs::fault::inject_errno("renameat2_noreplace", 1, libc::ENOENT);
        }
        let stats = reap_expired_with_budget(&mut queue, &WorkBudget::default());
        fs::fault::reset();
        assert_eq!(stats.leases_reaped, 0);
        assert_recorded_move_category(
            &stats,
            "reap_to_ready",
            if collision {
                "collision"
            } else {
                "source_missing"
            },
        );
        assert!(source.exists());
        if collision {
            assert!(destination.exists());
            std::fs::remove_file(&destination).unwrap();
        }
        queue.persist_recovery_cursor().unwrap();
        drop(queue);
        let mut reopened = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        let replay = reap_expired_with_budget(&mut reopened, &WorkBudget::default());
        assert_eq!(replay.leases_reaped, 1, "errors: {:?}", replay.errors);
        assert!(!source.exists());
        assert!(destination.exists());
    }
}

#[test]
fn reap_to_dead_scanner_handles_collision_and_missing_source() {
    for collision in [true, false] {
        let (tmp, mut queue) = create_test_queue();
        let lease = lease_recovery_job(&mut queue, 1);
        let parts = lease_path_parts(&lease);
        let common = lease_common(&lease);
        let wall_floor = queue.authenticated_wall_floor().unwrap();
        let source = tmp.path().join(&lease.exact_source_path);
        let destination = tmp
            .path()
            .join(dead_destination(&queue, parts[1], &common, wall_floor));
        queue
            .ensure_dir(
                destination
                    .parent()
                    .unwrap()
                    .strip_prefix(tmp.path())
                    .unwrap()
                    .to_str()
                    .unwrap(),
            )
            .unwrap();
        if collision {
            std::fs::copy(&source, &destination).unwrap();
        } else {
            fs::fault::inject_errno("renameat2_noreplace", 1, libc::ENOENT);
        }
        let stats = reap_expired_with_budget(&mut queue, &WorkBudget::default());
        fs::fault::reset();
        assert_eq!(stats.leases_to_dead, 0);
        assert_recorded_move_category(
            &stats,
            "reap_to_dead",
            if collision {
                "collision"
            } else {
                "source_missing"
            },
        );
        assert!(source.exists());
        if collision {
            assert!(destination.exists());
            std::fs::remove_file(&destination).unwrap();
        }
        queue.persist_recovery_cursor().unwrap();
        drop(queue);
        let mut reopened = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        let replay = reap_expired_with_budget(&mut reopened, &WorkBudget::default());
        assert_eq!(replay.leases_to_dead, 1, "errors: {:?}", replay.errors);
        assert!(!source.exists());
        assert!(destination.exists());
    }
}

#[test]
fn delayed_promotion_scanner_handles_collision_and_missing_source() {
    for collision in [true, false] {
        let (tmp, mut queue) = create_test_queue();
        let not_before = queue
            .authenticated_wall_floor()
            .unwrap()
            .unix_ns()
            .checked_add(queue.format.delayed_bucket_width_ns())
            .unwrap();
        let ticket = match queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".into(),
            initial_not_before: Some(not_before),
            payload: b"delayed collision".to_vec(),
            ..Default::default()
        }) {
            EnqueueOutcome::Committed(ticket) => ticket,
            outcome => panic!("enqueue failed: {outcome:?}"),
        };
        let parts = ticket.expected_relative_path.split('/').collect::<Vec<_>>();
        let parsed = steadq_names::parse_delayed(parts[3]).unwrap();
        let source = tmp.path().join(&ticket.expected_relative_path);
        let destination = tmp
            .path()
            .join(ready_destination(&queue, parts[2], &parsed.common));
        let delayed_bucket = steadq_names::bucket_from_hex(parts[1]).unwrap();
        write_wall_watermark(&tmp, delayed_bucket);
        let wall_floor = queue.authenticated_wall_floor().unwrap();
        if collision {
            std::fs::copy(&source, &destination).unwrap();
        } else {
            fs::fault::inject_errno("renameat2_noreplace", 1, libc::ENOENT);
        }
        let stats = promote_eligible_with_budget(&mut queue, wall_floor);
        fs::fault::reset();
        assert_eq!(stats.delayed_promoted, 0);
        assert_recorded_move_category(
            &stats,
            "promote_delayed",
            if collision {
                "collision"
            } else {
                "source_missing"
            },
        );
        assert!(source.exists());
        if collision {
            assert!(destination.exists());
            std::fs::remove_file(&destination).unwrap();
        }
        queue.persist_recovery_cursor().unwrap();
        drop(queue);
        let mut reopened = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        let replay_floor = reopened.authenticated_wall_floor().unwrap();
        let replay = promote_eligible_with_budget(&mut reopened, replay_floor);
        assert_eq!(replay.delayed_promoted, 1, "errors: {:?}", replay.errors);
        assert!(!source.exists());
        assert!(destination.exists());
    }
}

#[test]
fn recovery_skips_wall_sensitive_actions_without_watermark() {
    let (tmp, mut queue) = create_test_queue();
    let not_before = queue.authenticated_wall_floor().unwrap().unix_ns() + 60_000_000_000;
    let ticket = match queue.enqueue(crate::queue::EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".into(),
        initial_not_before: Some(not_before),
        payload: b"delayed".to_vec(),
        ..Default::default()
    }) {
        EnqueueOutcome::Committed(ticket) => ticket,
        outcome => panic!("enqueue failed: {outcome:?}"),
    };
    std::fs::remove_file(tmp.path().join("control/wall-watermark")).unwrap();

    let stats = queue.recover(&WorkBudget::default());
    assert_eq!(stats.delayed_promoted, 0);
    assert!(stats
        .errors
        .iter()
        .any(|error| error.operation == "wall_floor"));
    assert!(tmp.path().join(ticket.expected_relative_path).exists());
}

#[test]
fn recovery_promotes_eligible_delayed_job() {
    let (tmp, mut queue) = create_test_queue();
    let width = queue.format.delayed_bucket_width_ns();
    let not_before = queue
        .authenticated_wall_floor()
        .unwrap()
        .unix_ns()
        .checked_add(width)
        .unwrap();
    let ticket = match queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".into(),
        initial_not_before: Some(not_before),
        payload: b"delayed".to_vec(),
        ..Default::default()
    }) {
        EnqueueOutcome::Committed(ticket) => ticket,
        outcome => panic!("enqueue failed: {outcome:?}"),
    };
    let eligible_bucket = steadq_math::ceiling_bucket(not_before, width).unwrap();
    write_wall_watermark(&tmp, eligible_bucket);

    let stats = queue.recover(&WorkBudget::default());
    assert_eq!(stats.delayed_promoted, 1, "errors: {:?}", stats.errors);
    assert!(!tmp.path().join(ticket.expected_relative_path).exists());
    assert!(find_file(&tmp.path().join("ready"), "sqj").is_some());
}

#[test]
fn recovery_compacts_full_receipt() {
    let (tmp, mut queue) = create_test_queue();
    enqueue_and_ack(&mut queue);
    let receipt = find_file(&tmp.path().join("receipts"), "rct").unwrap();
    assert!(std::fs::metadata(&receipt).unwrap().len() > 128);

    let stats = queue.recover(&WorkBudget::default());
    assert_eq!(stats.receipts_compacted, 1, "errors: {:?}", stats.errors);
    assert_eq!(std::fs::metadata(receipt).unwrap().len(), 128);
}

#[test]
fn compaction_temporary_name_is_strict() {
    assert!(compaction_temporary_name(
        ".compact-0123456789abcdef0123456789abcdef.tmp"
    ));
    for invalid in [
        ".compact-0123456789abcdef0123456789abcde.tmp",
        ".compact-0123456789abcdef0123456789abcdef0.tmp",
        ".compact-0123456789ABCDEF0123456789ABCDEF.tmp",
        ".compact-0123456789abcdef0123456789abcdeg.tmp",
        "compact-0123456789abcdef0123456789abcdef.tmp",
        ".compact-0123456789abcdef0123456789abcdef.rct",
    ] {
        assert!(!compaction_temporary_name(invalid), "{invalid}");
    }
}

#[test]
fn recovery_compaction_fault_matrix_preserves_receipt_and_replays() {
    for (fault, count, errno, expected_operation, expected_phase, replaced) in [
        (
            "get_random",
            1,
            libc::EIO,
            "receipt_compact_temp_name_not_committed",
            "phase=TempName",
            false,
        ),
        (
            "openat",
            2,
            libc::EIO,
            "receipt_compact_temp_create_not_committed",
            "phase=TempCreate",
            false,
        ),
        (
            "write_all",
            1,
            libc::EIO,
            "receipt_compact_temp_write_not_committed",
            "phase=TempWrite",
            false,
        ),
        (
            "fsync",
            1,
            libc::EIO,
            "receipt_compact_temp_fsync_not_committed",
            "phase=TempFsync",
            false,
        ),
        (
            "fstatat",
            1,
            libc::EIO,
            "receipt_compact_replace_not_committed",
            "phase=DestinationIdentity",
            false,
        ),
        (
            "renameat",
            1,
            libc::EIO,
            "receipt_compact_replace_not_committed",
            "phase=Rename",
            false,
        ),
        (
            "renameat",
            1,
            libc::ENOENT,
            "receipt_compact_replace_source_missing",
            "source is missing",
            false,
        ),
        (
            "fsync_dir_fd",
            1,
            libc::EIO,
            "receipt_compact_replace_outcome_unknown",
            "phase=DestinationFsync",
            true,
        ),
        (
            "openat",
            1,
            libc::EIO,
            "receipt_compact_open",
            "os error 5",
            false,
        ),
        (
            "try_ofd_write_lock",
            1,
            libc::EIO,
            "receipt_compact_lock",
            "os error 5",
            false,
        ),
    ] {
        let (tmp, mut queue) = create_test_queue();
        enqueue_and_ack(&mut queue);
        let receipt = find_file(&tmp.path().join("receipts"), "rct").unwrap();

        fs::fault::reset();
        fs::fault::inject_errno(fault, count, errno);
        let stats = compact_receipts_with_budget(&mut queue);
        fs::fault::reset();

        assert_eq!(stats.receipts_compacted, 0);
        let error = stats
            .errors
            .iter()
            .find(|error| error.operation == expected_operation)
            .unwrap_or_else(|| panic!("missing {expected_operation}: {:?}", stats.errors));
        assert!(
            error.error.contains(expected_phase),
            "fault={fault} errors={:?}",
            stats.errors
        );
        assert_eq!(
            std::fs::metadata(&receipt).unwrap().len()
                == steadq_format::COMPACT_RECEIPT_SIZE as u64,
            replaced,
            "fault={fault} errors={:?}",
            stats.errors
        );
        let mut temporary_files = Vec::new();
        find_compaction_temporary_files(&tmp.path().join("receipts"), &mut temporary_files);
        assert!(temporary_files.is_empty(), "{temporary_files:?}");

        queue.persist_recovery_cursor().unwrap();
        drop(queue);
        let mut reopened = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        let replay = compact_receipts_with_budget(&mut reopened);
        assert_eq!(replay.receipts_compacted, u32::from(!replaced));
        assert_eq!(
            std::fs::metadata(receipt).unwrap().len(),
            steadq_format::COMPACT_RECEIPT_SIZE as u64
        );
    }
}

#[test]
fn recovery_compaction_cleanup_failures_are_reported_and_replayed() {
    for (cleanup_fault, expected_operation, temp_remains) in [
        (
            "unlinkat",
            "receipt_compact_temp_cleanup_not_committed",
            true,
        ),
        (
            "fsync_dir_fd",
            "receipt_compact_temp_cleanup_outcome_unknown",
            false,
        ),
    ] {
        let (tmp, mut queue) = create_test_queue();
        enqueue_and_ack(&mut queue);
        let receipt = find_file(&tmp.path().join("receipts"), "rct").unwrap();

        fs::fault::reset();
        fs::fault::inject_errno("write_all", 1, libc::EIO);
        fs::fault::inject_errno(cleanup_fault, 1, libc::EIO);
        let stats = compact_receipts_with_budget(&mut queue);
        fs::fault::reset();

        assert_eq!(stats.receipts_compacted, 0);
        assert!(stats
            .errors
            .iter()
            .any(|error| error.operation == "receipt_compact_temp_write_not_committed"));
        assert!(stats
            .errors
            .iter()
            .any(|error| error.operation == expected_operation));
        assert!(std::fs::metadata(&receipt).unwrap().len() > 128);
        let mut temporary_files = Vec::new();
        find_compaction_temporary_files(&tmp.path().join("receipts"), &mut temporary_files);
        assert_eq!(temporary_files.len(), usize::from(temp_remains));

        queue.persist_recovery_cursor().unwrap();
        drop(queue);
        let mut reopened = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        let replay = compact_receipts_with_budget(&mut reopened);
        assert_eq!(replay.receipts_compacted, 1, "errors: {:?}", replay.errors);
        assert_eq!(
            std::fs::metadata(receipt).unwrap().len(),
            steadq_format::COMPACT_RECEIPT_SIZE as u64
        );
        temporary_files.clear();
        find_compaction_temporary_files(&tmp.path().join("receipts"), &mut temporary_files);
        assert!(temporary_files.is_empty(), "{temporary_files:?}");
    }
}

#[test]
fn corrupt_full_receipt_is_never_compacted_or_accepted_as_duplicate() {
    let (tmp, mut queue) = create_test_queue();
    let lease = enqueue_and_ack(&mut queue);
    let receipt = find_file(&tmp.path().join("receipts"), "rct").unwrap();
    let mut bytes = std::fs::read(&receipt).unwrap();
    let payload_byte = bytes.last_mut().expect("full receipt has payload bytes");
    *payload_byte ^= 0xff;
    std::fs::write(&receipt, &bytes).unwrap();

    assert!(matches!(
        queue.check_duplicate_ack(&lease),
        AckOutcome::LeaseLost
    ));
    assert!(!queue
        .inspect(&lease.job_id)
        .iter()
        .any(|snapshot| snapshot.state == "receipt"));

    let stats = queue.recover(&WorkBudget::default());
    assert_eq!(stats.receipts_compacted, 0);
    assert!(stats
        .errors
        .iter()
        .any(|error| error.operation == "receipt_compact_invalid"));
    assert!(std::fs::metadata(&receipt).unwrap().len() > 128);

    let report = queue.fsck(&crate::FsckOptions::default());
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.finding_type == "receipt_verification_failed"));

    let repair = queue.fsck(&crate::FsckOptions {
        mode: crate::FsckMode::Repair,
        depth: crate::FsckDepth::Structural,
    });
    assert_eq!(repair.quarantined.len(), 1);
    assert!(!receipt.exists());
}

#[test]
fn legacy_compact_receipt_is_not_strict_evidence() {
    let (tmp, mut queue) = create_test_queue();
    let lease = enqueue_and_ack(&mut queue);
    let receipt = find_file(&tmp.path().join("receipts"), "rct").unwrap();
    let stats = queue.recover(&WorkBudget::default());
    assert_eq!(stats.receipts_compacted, 1, "errors: {:?}", stats.errors);

    let mut bytes = std::fs::read(&receipt).unwrap();
    bytes[10..12].copy_from_slice(&0u16.to_be_bytes());
    let digest = steadq_format::receipt_digest(&bytes[0..96]);
    bytes[96..128].copy_from_slice(&digest);
    std::fs::write(&receipt, bytes).unwrap();

    assert!(matches!(
        queue.check_duplicate_ack(&lease),
        AckOutcome::LeaseLost
    ));
    let report = queue.fsck(&crate::FsckOptions::default());
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.finding_type == "receipt_verification_failed"));
}

#[test]
fn recovery_deletes_receipt_after_authenticated_retention_floor() {
    let (tmp, mut queue) = create_test_queue();
    queue.options.receipt_retention_ns = 0;
    enqueue_and_ack(&mut queue);
    let receipt = find_file(&tmp.path().join("receipts"), "rct").unwrap();
    let receipt_bucket = receipt
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .file_name()
        .unwrap()
        .to_str()
        .and_then(|name| u64::from_str_radix(name, 16).ok())
        .unwrap();
    let expiration_floor = receipt_bucket
        .checked_add(1)
        .and_then(|bucket| bucket.checked_mul(queue.format.terminal_bucket_width_ns()))
        .unwrap();
    let watermark_bucket =
        steadq_math::ceiling_bucket(expiration_floor, queue.format.delayed_bucket_width_ns())
            .unwrap();
    write_wall_watermark(&tmp, watermark_bucket);

    let stats = queue.recover(&WorkBudget {
        max_duration_ms: 5_000,
        ..WorkBudget::default()
    });
    assert_eq!(stats.receipts_expired, 1, "errors: {:?}", stats.errors);
    assert!(!receipt.exists());
}

#[test]
fn receipt_shard_removal_preserves_phase_and_replays() {
    for (fault, expected_phase, outcome_unknown, shard_remains) in [
        (
            "unlinkat_dir",
            crate::queue::engine::RemoveDirectoryPhase::Remove,
            false,
            true,
        ),
        (
            "fsync_dir_fd",
            crate::queue::engine::RemoveDirectoryPhase::ParentFsync,
            true,
            false,
        ),
    ] {
        let (tmp, mut queue) = create_test_queue();
        let bucket_name = "0000000000000000";
        let shard_name = "0000";
        let bucket = tmp.path().join("receipts").join(bucket_name);
        let shard = bucket.join(shard_name);
        std::fs::create_dir_all(&shard).unwrap();
        let wall_floor = queue.authenticated_wall_floor().unwrap();

        fs::fault::reset();
        fs::fault::inject_errno(fault, 1, libc::EIO);
        let stats = delete_receipts_with_budget(&mut queue, wall_floor);
        fs::fault::reset();

        assert_recorded_remove_directory_failure(
            &stats,
            "receipt_shard_remove",
            &format!("receipts/{bucket_name}/{shard_name}"),
            expected_phase,
            outcome_unknown,
        );
        assert_eq!(stats.shards_removed, 0);
        assert_eq!(stats.buckets_removed, 0);
        assert_eq!(shard.exists(), shard_remains);
        assert!(bucket.exists());

        queue.persist_recovery_cursor().unwrap();
        drop(queue);
        let mut reopened = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        let replay_floor = reopened.authenticated_wall_floor().unwrap();
        let replay = delete_receipts_with_budget(&mut reopened, replay_floor);
        assert_eq!(
            replay.operations_attempted,
            1 + u32::from(shard_remains),
            "errors: {:?}",
            replay.errors
        );
        assert_eq!(replay.shards_removed, u32::from(shard_remains));
        assert_eq!(replay.buckets_removed, 1);
        assert!(!bucket.exists());
    }
}

#[test]
fn receipt_bucket_removal_preserves_phase_and_replays() {
    for (fault, expected_phase, outcome_unknown, bucket_remains) in [
        (
            "unlinkat_dir",
            crate::queue::engine::RemoveDirectoryPhase::Remove,
            false,
            true,
        ),
        (
            "fsync_dir_fd",
            crate::queue::engine::RemoveDirectoryPhase::ParentFsync,
            true,
            false,
        ),
    ] {
        let (tmp, mut queue) = create_test_queue();
        let bucket_name = "0000000000000000";
        let bucket = tmp.path().join("receipts").join(bucket_name);
        std::fs::create_dir(&bucket).unwrap();
        let wall_floor = queue.authenticated_wall_floor().unwrap();

        fs::fault::reset();
        fs::fault::inject_errno(fault, 1, libc::EIO);
        let stats = delete_receipts_with_budget(&mut queue, wall_floor);
        fs::fault::reset();

        assert_recorded_remove_directory_failure(
            &stats,
            "receipt_bucket_remove",
            &format!("receipts/{bucket_name}"),
            expected_phase,
            outcome_unknown,
        );
        assert_eq!(stats.shards_removed, 0);
        assert_eq!(stats.buckets_removed, 0);
        assert_eq!(bucket.exists(), bucket_remains);

        queue.persist_recovery_cursor().unwrap();
        drop(queue);
        let mut reopened = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        let replay_floor = reopened.authenticated_wall_floor().unwrap();
        let replay = delete_receipts_with_budget(&mut reopened, replay_floor);
        assert_eq!(
            replay.operations_attempted,
            u32::from(bucket_remains),
            "errors: {:?}",
            replay.errors
        );
        assert_eq!(replay.shards_removed, 0);
        assert_eq!(replay.buckets_removed, u32::from(bucket_remains));
        assert!(!bucket.exists());
    }
}

#[test]
fn recovery_unlink_failure_preserves_category_and_phase() {
    for (failure, expected_operation, expected_detail) in [
        (
            UnlinkFailure::NotCommitted {
                phase: UnlinkPhase::Unlink,
                source: std::io::Error::other("unlink failed"),
            },
            "delete_not_committed",
            "phase=Unlink",
        ),
        (
            UnlinkFailure::OutcomeUnknown {
                phase: UnlinkPhase::DirectoryFsync,
                source: std::io::Error::other("sync failed"),
            },
            "delete_outcome_unknown",
            "phase=DirectoryFsync",
        ),
        (
            UnlinkFailure::SourceMissing,
            "delete_source_missing",
            "source is missing",
        ),
    ] {
        let mut stats = RecoveryStats::default();
        Queue::record_unlink_failure(&mut stats, "delete", "source/path", failure);
        assert_eq!(stats.errors.len(), 1);
        assert_eq!(stats.errors[0].operation, expected_operation);
        assert_eq!(stats.errors[0].relative_path, "source/path");
        assert!(stats.errors[0].error.contains(expected_detail));
    }
}

#[test]
fn recovery_replace_failure_preserves_category_and_phase() {
    for (failure, expected_operation, expected_detail) in [
        (
            ReplaceFailure::NotCommitted {
                phase: ReplacePhase::Rename,
                source: std::io::Error::other("rename failed"),
            },
            "replace_not_committed",
            "phase=Rename",
        ),
        (
            ReplaceFailure::OutcomeUnknown {
                phase: ReplacePhase::DestinationFsync,
                source: std::io::Error::other("sync failed"),
            },
            "replace_outcome_unknown",
            "phase=DestinationFsync",
        ),
        (
            ReplaceFailure::SourceMissing,
            "replace_source_missing",
            "source is missing",
        ),
        (
            ReplaceFailure::DestinationChanged,
            "replace_destination_changed",
            "destination identity changed",
        ),
    ] {
        let mut stats = RecoveryStats::default();
        Queue::record_replace_failure(&mut stats, "replace", "receipt/path", failure);
        assert_eq!(stats.errors.len(), 1);
        assert_eq!(stats.errors[0].operation, expected_operation);
        assert_eq!(stats.errors[0].relative_path, "receipt/path");
        assert!(stats.errors[0].error.contains(expected_detail));
    }
}

#[test]
fn temporary_cleanup_records_unlink_phase_without_counting_commit() {
    for (fault, errno, phase, category, file_remains) in [
        (
            "unlinkat",
            libc::EIO,
            Some(UnlinkPhase::Unlink),
            "not_committed",
            true,
        ),
        (
            "fsync_dir_fd",
            libc::EIO,
            Some(UnlinkPhase::DirectoryFsync),
            "outcome_unknown",
            false,
        ),
        ("unlinkat", libc::ENOENT, None, "source_missing", true),
    ] {
        let (tmp, mut queue) = create_test_queue();
        let old_boot = "00000000-0000-0000-0000-000000000000";
        assert_ne!(queue.boot_id, old_boot);
        let shard = tmp.path().join(format!("tmp/{old_boot}/0000"));
        std::fs::create_dir_all(&shard).unwrap();
        let path = shard.join(steadq_names::temp_filename(0, &[0xAB; 16]));
        std::fs::write(&path, b"temp").unwrap();

        fs::fault::reset();
        fs::fault::inject_errno(fault, 1, errno);
        let stats = cleanup_temp_with_budget(&mut queue);
        fs::fault::reset();
        assert_eq!(stats.temp_files_deleted, 0);
        assert_eq!(path.exists(), file_remains);
        if let Some(phase) = phase {
            assert_recorded_unlink_failure(
                &stats,
                "temp_delete",
                phase,
                category == "outcome_unknown",
            );
        } else {
            assert_eq!(stats.operations_attempted, 1);
            assert_eq!(stats.errors.len(), 1);
            assert_eq!(stats.errors[0].operation, "temp_delete_source_missing");
        }
        queue.persist_recovery_cursor().unwrap();
        drop(queue);
        let mut reopened = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        let replay = cleanup_temp_with_budget(&mut reopened);
        assert_eq!(replay.temp_files_deleted, u32::from(file_remains));
        assert!(!path.exists());
    }
}

#[test]
fn receipt_deletion_records_unlink_phase_without_counting_commit() {
    for (fault, errno, phase, category, file_remains) in [
        (
            "unlinkat",
            libc::EIO,
            Some(UnlinkPhase::Unlink),
            "not_committed",
            true,
        ),
        (
            "fsync_dir_fd",
            libc::EIO,
            Some(UnlinkPhase::DirectoryFsync),
            "outcome_unknown",
            false,
        ),
        ("unlinkat", libc::ENOENT, None, "source_missing", true),
    ] {
        let (tmp, mut queue) = create_test_queue();
        enqueue_and_ack(&mut queue);
        let receipt = find_file(&tmp.path().join("receipts"), "rct").unwrap();
        let shard_dir = receipt.parent().unwrap().to_path_buf();
        if let Some(bucket_dir) = shard_dir.parent() {
            for entry in std::fs::read_dir(bucket_dir).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() && path != shard_dir {
                    let _ = std::fs::remove_dir(&path);
                }
            }
        }
        let receipt_bucket = receipt
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_str()
            .and_then(steadq_names::bucket_from_hex)
            .unwrap();
        let expiration_floor = receipt_bucket
            .checked_add(1)
            .and_then(|bucket| bucket.checked_mul(queue.format.terminal_bucket_width_ns()))
            .unwrap();
        let watermark_bucket =
            steadq_math::ceiling_bucket(expiration_floor, queue.format.delayed_bucket_width_ns())
                .unwrap();
        write_wall_watermark(&tmp, watermark_bucket);
        let wall_floor = queue.authenticated_wall_floor().unwrap();

        fs::fault::reset();
        fs::fault::inject_errno(fault, 1, errno);
        let stats = delete_receipts_with_budget(&mut queue, wall_floor);
        fs::fault::reset();
        assert_eq!(stats.receipts_expired, 0);
        assert_eq!(receipt.exists(), file_remains);
        if let Some(phase) = phase {
            assert_recorded_unlink_failure(
                &stats,
                "receipt_delete",
                phase,
                category == "outcome_unknown",
            );
        } else {
            assert_eq!(stats.operations_attempted, 2);
            assert_eq!(stats.errors.len(), 1);
            assert_eq!(stats.errors[0].operation, "receipt_delete_source_missing");
        }
        queue.persist_recovery_cursor().unwrap();
        drop(queue);
        let mut reopened = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        let replay_floor = reopened.authenticated_wall_floor().unwrap();
        let replay = delete_receipts_with_budget(&mut reopened, replay_floor);
        assert_eq!(replay.receipts_expired, u32::from(file_remains));
        assert!(!receipt.exists());
    }
}

#[test]
fn missing_receipt_during_compact_is_a_skip_not_an_error() {
    let (_tmp, mut queue) = create_test_queue();
    enqueue_and_ack(&mut queue);
    fs::fault::reset();
    fs::fault::inject_errno("openat", 1, libc::ENOENT);
    let stats = compact_receipts_with_budget(&mut queue);
    fs::fault::reset();
    assert_eq!(stats.receipts_compacted, 0);
    assert!(
        stats.errors.is_empty(),
        "ENOENT during receipt open must skip, not record: {:?}",
        stats.errors
    );
}

#[test]
fn receipt_deletion_records_open_and_lock_io() {
    for (fault, expected_operation) in [
        ("openat", "receipt_delete_open"),
        ("try_ofd_write_lock", "receipt_delete_lock"),
    ] {
        let (tmp, mut queue) = create_test_queue();
        enqueue_and_ack(&mut queue);
        let receipt = find_file(&tmp.path().join("receipts"), "rct").unwrap();
        let receipt_bucket = receipt
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_str()
            .and_then(steadq_names::bucket_from_hex)
            .unwrap();
        let expiration_floor = receipt_bucket
            .checked_add(1)
            .and_then(|bucket| bucket.checked_mul(queue.format.terminal_bucket_width_ns()))
            .unwrap();
        let watermark_bucket =
            steadq_math::ceiling_bucket(expiration_floor, queue.format.delayed_bucket_width_ns())
                .unwrap();
        write_wall_watermark(&tmp, watermark_bucket);
        let wall_floor = queue.authenticated_wall_floor().unwrap();

        fs::fault::reset();
        fs::fault::inject_errno(fault, 1, libc::EIO);
        let stats = delete_receipts_with_budget(&mut queue, wall_floor);
        fs::fault::reset();
        assert_eq!(stats.receipts_expired, 0);
        assert!(receipt.exists());
        assert!(
            stats
                .errors
                .iter()
                .any(|error| error.operation == expected_operation),
            "missing {expected_operation}: {:?}",
            stats.errors
        );
        queue.persist_recovery_cursor().unwrap();
        drop(queue);
        let mut reopened = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        let replay_floor = reopened.authenticated_wall_floor().unwrap();
        let replay = delete_receipts_with_budget(&mut reopened, replay_floor);
        assert_eq!(replay.receipts_expired, 1, "errors: {:?}", replay.errors);
        assert!(!receipt.exists());
    }
}

#[test]
fn recovery_uses_one_wall_snapshot() {
    let (_tmp, mut queue) = create_test_queue();
    fs::fault::reset();
    fs::fault::inject("clock_realtime_ns", 2);
    let stats = queue.recover(&WorkBudget::default());
    assert!(!stats
        .errors
        .iter()
        .any(|error| error.operation == "wall_floor"));
    assert_eq!(fs::fault::call_count("clock_realtime_ns"), 1);
    fs::fault::reset();
}

#[test]
fn recovery_stabilizes_wall_floor_before_wall_sensitive_phases() {
    let (tmp, mut queue) = create_test_queue();
    write_wall_watermark(&tmp, 0);

    let stats = queue.recover(&WorkBudget::default());
    assert!(!stats
        .errors
        .iter()
        .any(|error| error.operation == "wall_floor"));
    let bytes = std::fs::read(tmp.path().join("control/wall-watermark")).unwrap();
    let watermark = steadq_format::WatermarkRecord::decode(&bytes).unwrap();
    assert!(watermark.highest_observed_bucket > 0);
}

#[test]
fn recovery_does_not_invent_terminal_bucket_without_wall_floor() {
    let (tmp, mut queue) = create_test_queue();
    assert!(matches!(
        queue.enqueue(crate::queue::EnqueueInput {
            maximum_attempts: 1,
            content_type: "x".into(),
            payload: b"terminal".to_vec(),
            ..Default::default()
        }),
        EnqueueOutcome::Committed(_)
    ));
    let lease = match queue.lease(0, 1_000_000_000) {
        LeaseOutcome::Leased(lease) => lease,
        outcome => panic!("lease failed: {outcome:?}"),
    };
    let mut stats = RecoveryStats::default();
    let scan_budget = RecoveryScanBudget::default();
    let mut scan_stats = RecoveryScanStats::default();
    let mut scan = RecoveryScanContext {
        budget: &scan_budget,
        stats: &mut scan_stats,
    };
    queue.reap_expired_leases(
        u64::MAX,
        None,
        &WorkBudget::default(),
        &mut scan,
        &mut stats,
        u64::MAX,
    );

    assert_eq!(stats.leases_to_dead, 0);
    assert!(stats
        .errors
        .iter()
        .any(|error| error.operation == "reap_to_dead"));
    assert!(tmp.path().join(&lease.exact_source_path).exists());
    assert!(!tmp.path().join("dead/0000000000000000").exists());
}

#[test]
fn colocated_reap_resumes_from_the_persisted_shard() {
    let (tmp, mut queue) = create_test_queue_with_shards(2);
    for shard in [0, 1] {
        enqueue_for_shard(&mut queue, &tmp, shard, None, b"colocated");
        assert!(matches!(
            queue.lease(0, 30_000_000_000),
            LeaseOutcome::Leased(_)
        ));
    }
    let budget = WorkBudget {
        max_operations: 1,
        max_duration_ms: 5_000,
    };
    let first = reap_expired_with_budget(&mut queue, &budget);
    assert_eq!(first.leases_reaped, 1, "errors: {:?}", first.errors);
    assert!(first.budget_exhausted);
    assert_eq!(queue.recovery_cursor.reap_colocated_shard, Some(1));

    queue.persist_recovery_cursor().unwrap();
    drop(queue);
    let mut reopened = Queue::open(
        tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(reopened.recovery_cursor.reap_colocated_shard, Some(1));

    let second = reap_expired_with_budget(&mut reopened, &budget);
    assert_eq!(second.leases_reaped, 1, "errors: {:?}", second.errors);
    assert!(!second.budget_exhausted);
    assert_eq!(reopened.recovery_cursor.reap_colocated_shard, None);
}

#[test]
fn promote_quarantines_a_malformed_delayed_name() {
    let (tmp, mut queue) = create_test_queue();
    queue.ensure_dir("delayed/0000000000000000/0000").unwrap();
    let stray = tmp.path().join("delayed/0000000000000000/0000/garbage.sqj");
    std::fs::write(&stray, b"garbage").unwrap();
    let wall_floor = queue.authenticated_wall_floor().unwrap();
    let stats = promote_eligible_with_budget(&mut queue, wall_floor);
    assert!(
        stats.errors.iter().any(|e| e.operation == "promote_parse"),
        "errors: {:?}",
        stats.errors
    );
    assert!(!stray.exists());
    assert_eq!(queue.list_quarantine().len(), 1);
}

#[test]
fn receipt_retention_quarantines_a_malformed_receipt_name() {
    let (tmp, mut queue) = create_test_queue();
    queue.ensure_dir("receipts/0000000000000000/0000").unwrap();
    let stray = tmp
        .path()
        .join("receipts/0000000000000000/0000/garbage.rct");
    std::fs::write(&stray, b"garbage").unwrap();
    let wall_floor = queue.authenticated_wall_floor().unwrap();
    let stats = delete_receipts_with_budget(&mut queue, wall_floor);
    assert!(
        stats
            .errors
            .iter()
            .any(|e| e.operation == "receipt_delete_parse"),
        "errors: {:?}",
        stats.errors
    );
    assert!(!stray.exists());
    assert_eq!(queue.list_quarantine().len(), 1);
}
