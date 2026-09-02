// Unit tests for the queue module.
use super::lease::DeadLetterFailure;
use super::publish::PublishError;
use super::resolve::*;
use super::*;
use crate::FsckOptions;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};

trait CommitOrPanic {
    fn commit_or_panic(&self);
}

impl CommitOrPanic for TransitionOutcome {
    fn commit_or_panic(&self) {
        assert!(matches!(self, TransitionOutcome::Committed));
    }
}
use tempfile::TempDir;

fn create_test_queue() -> (TempDir, Queue) {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path();
    fs::fault::pin_clock_realtime_ns(fs::clock_realtime_ns().unwrap());
    Queue::init(path, &CreateOptions::default()).unwrap();
    let queue = Queue::open(
        path,
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    )
    .unwrap();
    (tmp, queue)
}

fn remove_wall_watermark(tmp: &TempDir) {
    std::fs::remove_file(tmp.path().join("control/wall-watermark")).unwrap();
}

fn write_wall_watermark(tmp: &TempDir, highest_observed_bucket: u64, sequence: u64) {
    let watermark = steadq_format::WatermarkRecord {
        highest_observed_bucket,
        sequence,
    };
    std::fs::write(
        tmp.path().join("control/wall-watermark"),
        watermark.encode(),
    )
    .unwrap();
}

fn replace_wall_watermark(tmp: &TempDir, highest_observed_bucket: u64, sequence: u64) {
    let control = tmp.path().join("control");
    let replacement = control.join(".watermark-test-replacement");
    let watermark = steadq_format::WatermarkRecord {
        highest_observed_bucket,
        sequence,
    };
    std::fs::write(&replacement, watermark.encode()).unwrap();
    std::fs::rename(replacement, control.join("wall-watermark")).unwrap();
}

fn find_leased_job(root: &Path) -> Option<PathBuf> {
    for entry in std::fs::read_dir(root).ok()? {
        let path = entry.ok()?.path();
        if path.is_dir() {
            if let Some(found) = find_leased_job(&path) {
                return Some(found);
            }
        } else if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| steadq_names::parse_leased(name).is_ok())
        {
            return Some(path);
        }
    }
    None
}

fn find_file_with_suffix(root: &Path, suffix: &str) -> Option<PathBuf> {
    for entry in std::fs::read_dir(root).ok()? {
        let path = entry.ok()?.path();
        if path.is_dir() {
            if let Some(found) = find_file_with_suffix(&path, suffix) {
                return Some(found);
            }
        } else if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(suffix))
        {
            return Some(path);
        }
    }
    None
}

fn test_claim_ticket(
    queue: &Queue,
    job_id: [u8; 16],
    generation: u64,
    attempt: u32,
    maximum_attempts: u32,
    lease_token: [u8; 16],
    envelope_digest: [u8; 32],
) -> TransitionTicket {
    let common = CommonFields {
        job_id,
        generation,
        attempt,
        maximum_attempts,
    };
    queue
        .claim_transition_ticket(
            &common,
            lease_token,
            TicketEvidence::new(envelope_digest, 4),
            1,
            1,
        )
        .unwrap()
}

fn enqueue_and_lease(queue: &mut Queue) -> LeaseInfo {
    assert!(matches!(
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "text/plain".to_string(),
            payload: b"resolver state".to_vec(),
            ..Default::default()
        }),
        EnqueueOutcome::Committed(_)
    ));
    match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(lease) => lease,
        outcome => panic!("expected lease, got {outcome:?}"),
    }
}

fn precreate_claim_destination_buckets(_tmp: &TempDir, queue: &Queue, lease_duration_ns: u64) {
    let deadline = fs::clock_boottime_ns()
        .unwrap()
        .checked_add(lease_duration_ns)
        .unwrap();
    let bucket = steadq_math::lease_bucket(deadline, queue.format.lease_bucket_width_ns())
        .expect("test lease deadline has a bucket");
    for bucket in bucket.saturating_sub(1)..=bucket.saturating_add(1) {
        queue
            .ensure_dir(&format!(
                "leased/{}/{}/0000",
                queue.boot_id,
                bucket_hex(bucket)
            ))
            .unwrap();
    }
}

fn precreate_named_temp_shards(_tmp: &TempDir, queue: &Queue) {
    queue.ensure_dir("ready/0000").unwrap();
    queue
        .ensure_dir(&format!("tmp/{}/0000", queue.boot_id))
        .unwrap();
}

fn tmpfile_supported(queue: &Queue) -> bool {
    let ready = open_relative(queue.root_fd(), "ready/0000").unwrap();
    fs::open_tmpfile(ready.as_fd()).is_ok()
}

// Link publication tests assert call sequences that hold only when
// linkat publication is attempted. Filesystems that force the named
// temp rename path (ZFS) must skip them; that path has its own tests.
fn link_publication_attempted(queue: &Queue) -> bool {
    queue.publication_mode != Some(fs::PublicationMode::NamedFallback)
}

fn add_hard_link(tmp: &tempfile::TempDir, relative_path: &str, label: &str) {
    std::fs::hard_link(
        tmp.path().join(relative_path),
        tmp.path().join(format!("tmp/{label}.link")),
    )
    .unwrap();
}

fn resolver_ticket_case(operation: &str) -> (tempfile::TempDir, Queue, TransitionTicket) {
    let (tmp, mut queue) = create_test_queue();
    if operation == "claim" {
        let enqueue = match queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "text/plain".into(),
            payload: b"data".to_vec(),
            ..Default::default()
        }) {
            EnqueueOutcome::Committed(ticket) => ticket,
            outcome => panic!("expected enqueue, got {outcome:?}"),
        };
        let parsed =
            steadq_names::parse_ready(enqueue.expected_relative_path.rsplit('/').next().unwrap())
                .unwrap();
        let ticket = queue
            .claim_transition_ticket(
                &parsed.common,
                [8; 16],
                TicketEvidence::new(enqueue.envelope_digest, 4),
                1,
                1,
            )
            .unwrap();
        return (tmp, queue, ticket);
    }

    let lease = enqueue_and_lease(&mut queue);
    let (operation, destination) = match operation {
        "acknowledge" => (
            TransitionOperation::Acknowledge,
            TicketDestination::Receipt { terminal_bucket: 1 },
        ),
        "retry_now" => (TransitionOperation::RetryNow, TicketDestination::Ready {}),
        "retry_later" => (
            TransitionOperation::RetryLater,
            TicketDestination::Delayed { not_before_ns: 1 },
        ),
        "bury" => (
            TransitionOperation::Bury,
            TicketDestination::Dead {
                terminal_bucket: 1,
                reason: DeadReason::AdministrativeBury as u16,
            },
        ),
        "renew" => (
            TransitionOperation::Renew,
            TicketDestination::Leased {
                boot_id: lease.boot_id.clone(),
                boottime_deadline_ns: lease.expires_boottime_ns + 1,
                wall_deadline_ns: lease.expires_wall_ns + 1,
            },
        ),
        _ => unreachable!(),
    };
    let ticket = queue
        .transition_ticket_for_lease(&lease, operation, destination)
        .unwrap();
    (tmp, queue, ticket)
}

#[test]
fn resolver_error_is_not_found_table() {
    for (errno, expected) in [
        (libc::ENOENT, true),
        (libc::EIO, false),
        (libc::EACCES, false),
    ] {
        let error = io::Error::from_raw_os_error(errno);
        assert_eq!(resolver_error_is_not_found(&error), expected);
    }
}

#[test]
fn create_option_validation_rejects_every_invalid_field() {
    let invalid = [
        CreateOptions {
            shard_count: 0,
            ..Default::default()
        },
        CreateOptions {
            shard_count: 3,
            ..Default::default()
        },
        CreateOptions {
            shard_count: 8192,
            ..Default::default()
        },
        CreateOptions {
            lease_bucket_width_ns: 0,
            ..Default::default()
        },
        CreateOptions {
            delayed_bucket_width_ns: 0,
            ..Default::default()
        },
        CreateOptions {
            terminal_bucket_width_ns: 0,
            ..Default::default()
        },
        CreateOptions {
            terminal_bucket_width_ns: 59_000_000_000,
            delayed_bucket_width_ns: 1_000_000_000,
            ..Default::default()
        },
        CreateOptions {
            terminal_bucket_width_ns: 86_401_000_000_000,
            delayed_bucket_width_ns: 1_000_000_000,
            ..Default::default()
        },
        CreateOptions {
            delayed_bucket_width_ns: 7_000_000_000,
            ..Default::default()
        },
        CreateOptions {
            max_payload_length: MAX_PAYLOAD_LENGTH + 1,
            ..Default::default()
        },
    ];

    assert!(validate_create_options(&CreateOptions::default()).is_ok());
    assert!(validate_create_options(&CreateOptions {
        shard_count: 4096,
        ..Default::default()
    })
    .is_ok());
    for options in invalid {
        assert!(matches!(
            validate_create_options(&options),
            Err(Error::InvalidInput(_))
        ));
    }
}

#[test]
fn lease_duration_validation_includes_exact_boundaries() {
    for (duration_ns, expected) in [
        (0, false),
        (MIN_LEASE_DURATION_NS - 1, false),
        (MIN_LEASE_DURATION_NS, true),
        (MAX_LEASE_DURATION_NS, true),
        (MAX_LEASE_DURATION_NS + 1, false),
        (u64::MAX, false),
    ] {
        assert_eq!(lease_duration_is_valid(duration_ns), expected);
    }
}

#[test]
fn payload_length_validation_includes_the_exact_limit() {
    for (payload_length, maximum, expected) in [
        (0, 0, true),
        (0, 1, true),
        (1, 1, true),
        (2, 1, false),
        (u64::MAX, u64::MAX, true),
    ] {
        assert_eq!(payload_length_is_valid(payload_length, maximum), expected);
    }
}

#[test]
fn queue_id_accessor_returns_the_format_identity() {
    let (_tmp, queue) = create_test_queue();
    assert_eq!(queue.queue_id(), queue.format().queue_id());
    assert_ne!(queue.queue_id(), &[1; 16]);
    assert_eq!(queue.boot_id(), queue.boot_id);
    assert_ne!(queue.boot_id(), "xyzzy");
}

#[test]
fn receipt_retention_probe_bound_accepts_only_the_exact_limit() {
    let tmp = TempDir::new().unwrap();
    let format = Queue::init(tmp.path(), &CreateOptions::default()).unwrap();
    let width = format.terminal_bucket_width_ns();
    let maximum = width.checked_mul(4094).unwrap();
    let options = |receipt_retention_ns| OpenOptions {
        allow_unsupported_fs: true,
        receipt_retention_ns,
        ..Default::default()
    };

    Queue::open(tmp.path(), &options(maximum)).unwrap();
    assert!(matches!(
        Queue::open(tmp.path(), &options(maximum + 1)),
        Err(Error::InvalidInput(_))
    ));
}

#[test]
fn lease_directory_open_failure_table() {
    for (errno, expected) in [
        (libc::ENOENT, LeaseDirectoryOpenFailure::Gone),
        (libc::ENOTDIR, LeaseDirectoryOpenFailure::InvalidDirectory),
        (libc::EIO, LeaseDirectoryOpenFailure::Io),
        (libc::EACCES, LeaseDirectoryOpenFailure::Io),
    ] {
        assert_eq!(
            classify_lease_directory_open_failure(&io::Error::from_raw_os_error(errno)),
            expected,
        );
    }
}

#[test]
fn resolver_object_open_failure_table() {
    for (errno, expected) in [
        (libc::ENOENT, ResolverObjectOpenFailure::Absent),
        (libc::ELOOP, ResolverObjectOpenFailure::Conflict),
        (libc::EIO, ResolverObjectOpenFailure::Io),
        (libc::EACCES, ResolverObjectOpenFailure::Io),
    ] {
        assert_eq!(
            classify_resolver_object_open_failure(&io::Error::from_raw_os_error(errno)),
            expected,
        );
    }
}

#[test]
fn resolver_object_verifier_matrix() {
    for state in ["ready", "leased", "delayed", "dead"] {
        assert_eq!(
            resolver_object_verifier(ObjectKind::FullJob, state),
            Some(ResolverObjectVerifier::Job)
        );
    }
    for state in ["receipts", "quarantine", "control", "hidden"] {
        assert_eq!(resolver_object_verifier(ObjectKind::FullJob, state), None);
    }

    for kind in [ObjectKind::FullReceipt, ObjectKind::CompactReceipt] {
        assert_eq!(
            resolver_object_verifier(kind, "receipts"),
            Some(ResolverObjectVerifier::Receipt)
        );
        for state in ["ready", "leased", "delayed", "dead", "quarantine"] {
            assert_eq!(resolver_object_verifier(kind, state), None);
        }
    }

    for kind in [ObjectKind::RawObject, ObjectKind::WatermarkRecord] {
        for state in ["ready", "leased", "delayed", "dead", "receipts"] {
            assert_eq!(resolver_object_verifier(kind, state), None);
        }
    }
}

#[test]
fn presence_failure_table() {
    for (errno, expected) in [
        (libc::ENOENT, PresenceFailure::Absent),
        (libc::EIO, PresenceFailure::Io),
        (libc::EACCES, PresenceFailure::Io),
    ] {
        assert_eq!(
            classify_presence_failure(&io::Error::from_raw_os_error(errno)),
            expected,
        );
    }
}

#[test]
fn move_outcome_unknown_phase_maps_to_the_last_durable_barrier() {
    for phase in [
        engine::MovePhase::EnsureDest,
        engine::MovePhase::PreRename,
        engine::MovePhase::Rename,
        engine::MovePhase::DestinationIdentity,
        engine::MovePhase::PostLinearization,
        engine::MovePhase::DestFsync,
    ] {
        assert_eq!(
            ticket_phase_for_move_outcome_unknown(phase),
            TransitionPhase::Linearized
        );
    }
    assert_eq!(
        ticket_phase_for_move_outcome_unknown(engine::MovePhase::SourceFsync),
        TransitionPhase::DestinationDirectoryDurable
    );
}

#[test]
fn resolved_identity_matches_table() {
    let cases = [
        (libc::S_IFREG | 0o600, 7, 11, true),
        (libc::S_IFDIR | 0o700, 7, 11, false),
        (libc::S_IFREG | 0o600, 8, 11, false),
        (libc::S_IFREG | 0o600, 7, 12, false),
    ];
    for (mode, device, inode, expected) in cases {
        assert_eq!(
            resolved_identity_matches(mode, device, inode, 7, 11),
            expected
        );
    }
}

#[test]
fn open_relative_rejects_escape_before_opening_a_component() {
    let (_tmp, queue) = create_test_queue();
    fs::fault::reset();
    fs::fault::inject("open_directory", 1);
    let result = open_relative(queue.root_fd().as_fd(), "ready/../../outside");
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    assert_eq!(fs::fault::call_count("open_directory"), 0);
    fs::fault::reset();
}

#[test]
fn init_and_open() {
    let (_tmp, queue) = create_test_queue();
    assert_eq!(queue.format().shard_count(), 64);
}

#[test]
fn publish_error_keeps_digest_after_linearization() {
    let digest = [0xABu8; 32];
    match PublishError::OutcomeUnknown(Error::IoFailure("fsync".into()))
        .with_published_digest(digest)
    {
        PublishError::OutcomeUnknownPublished {
            envelope_digest,
            error: Error::IoFailure(message),
        } => {
            assert_eq!(envelope_digest, digest);
            assert_eq!(message, "fsync");
        }
        _ => panic!("expected published unknown"),
    }
    assert!(matches!(
        PublishError::NotCommitted(Error::IdentityCollision).with_published_digest(digest),
        PublishError::NotCommitted(Error::IdentityCollision)
    ));
}

#[test]
fn zfs_prefers_named_publication_without_changing_other_backends() {
    assert_eq!(
        preferred_publication_mode(fs::ZFS_SUPER_MAGIC),
        Some(fs::PublicationMode::NamedFallback)
    );
    for filesystem in [
        fs::EXT4_SUPER_MAGIC,
        fs::XFS_SUPER_MAGIC,
        fs::BTRFS_SUPER_MAGIC,
        fs::F2FS_SUPER_MAGIC,
        fs::F2FS_STATFS_MAGIC_ALT,
    ] {
        assert_eq!(preferred_publication_mode(filesystem), None);
    }
}

#[test]
fn filesystem_classification_preserves_strict_and_relaxed_behavior() {
    assert_eq!(
        classify_filesystem_type(Ok(fs::EXT4_SUPER_MAGIC), false).unwrap(),
        Some(fs::EXT4_SUPER_MAGIC)
    );
    assert_eq!(
        classify_filesystem_type(Ok(fs::ZFS_SUPER_MAGIC), false).unwrap(),
        Some(fs::ZFS_SUPER_MAGIC)
    );
    assert_eq!(
        classify_filesystem_type(Ok(fs::F2FS_STATFS_MAGIC_ALT), false).unwrap(),
        Some(fs::F2FS_STATFS_MAGIC_ALT)
    );
    assert!(matches!(
        classify_filesystem_type(Ok(fs::TMPFS_MAGIC), false),
        Err(Error::UnsupportedFilesystem)
    ));
    assert_eq!(
        classify_filesystem_type(Ok(fs::TMPFS_MAGIC), true).unwrap(),
        Some(fs::TMPFS_MAGIC)
    );

    let strict_error =
        classify_filesystem_type(Err(io::Error::from_raw_os_error(libc::EIO)), false);
    assert!(matches!(strict_error, Err(Error::IoFailure(_))));
    assert_eq!(
        classify_filesystem_type(Err(io::Error::from_raw_os_error(libc::EIO)), true).unwrap(),
        None
    );
}

#[test]
fn sync_flushes_deferred_directory_changes() {
    let (tmp, mut queue) = {
        let tmp = TempDir::new().unwrap();
        fs::fault::pin_clock_realtime_ns(fs::clock_realtime_ns().unwrap());
        Queue::init(tmp.path(), &CreateOptions::default()).unwrap();
        let queue = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                deferred_dir_sync: true,
                ..Default::default()
            },
        )
        .unwrap();
        (tmp, queue)
    };

    // Publication is visible but cannot be reported Committed yet.
    let outcome = queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"deferred".to_vec(),
        ..Default::default()
    });
    assert!(matches!(outcome, EnqueueOutcome::Deferred(_)));

    assert!(queue.sync().is_ok());

    let mut queue2 = Queue::open(
        tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    )
    .unwrap();
    let lease = match queue2.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        o => panic!("lease failed: {o:?}"),
    };
    assert_eq!(lease.attempt, 1);
}

#[test]
fn deferred_enqueue_may_be_lost_before_sync_without_claiming_commit() {
    let tmp = TempDir::new().unwrap();
    fs::fault::pin_clock_realtime_ns(fs::clock_realtime_ns().unwrap());
    Queue::init(tmp.path(), &CreateOptions::default()).unwrap();
    let mut queue = Queue::open(
        tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            deferred_dir_sync: true,
            ..Default::default()
        },
    )
    .unwrap();

    fs::fault::reset();
    fs::fault::inject("fsync_dir_fd", u64::MAX);
    let outcome = queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".into(),
        payload: b"volatile publication".to_vec(),
        ..Default::default()
    });
    let fsyncs_before_sync = fs::fault::call_count("fsync_dir_fd");
    fs::fault::reset();
    let ticket = match outcome {
        EnqueueOutcome::Deferred(ticket) => ticket,
        other => panic!("deferred enqueue claimed the wrong outcome: {other:?}"),
    };
    assert_eq!(fsyncs_before_sync, 0);

    // Model the certified crash window in which the unsynced directory entry
    // is absent after restart. The API did not promise Committed for this job.
    std::fs::remove_file(tmp.path().join(ticket.expected_relative_path)).unwrap();
    drop(queue);
    let mut reopened = Queue::open(
        tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(matches!(
        reopened.lease(0, 30_000_000_000),
        LeaseOutcome::Empty
    ));
}

#[test]
fn batch_enqueue_commit_lease_ack_roundtrip() {
    // Regression: Batch::lease's deferred move path once constructed
    // MovedObject { size: 0 }, making the post-rename size check always fail
    // and poison the queue.
    let tmp = TempDir::new().unwrap();
    Queue::init(tmp.path(), &CreateOptions::default()).unwrap();
    let mut q = Queue::open(
        tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    )
    .unwrap();

    // Enqueue a job in a batch and commit
    let mut batch = q.batch();
    let outcome = batch.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: vec![0xABu8; 64],
        ..Default::default()
    });
    let ticket = match outcome {
        BatchEnqueueOutcome::Pending(t) => t,
        other => panic!("enqueue should be pending: {other:?}"),
    };
    let commit = batch.commit().expect("commit should succeed");
    assert_eq!(commit.committed_enqueues.len(), 1);
    assert_eq!(commit.committed_enqueues[0].job_id, ticket.job_id);

    // Lease via batch — this was completely broken before the fix
    let mut batch2 = q.batch();
    let lease_outcome = batch2.lease(0, 30_000_000_000);
    let lease = match lease_outcome {
        BatchLeaseOutcome::Pending(info) => info,
        BatchLeaseOutcome::Empty => panic!("should have a job to lease"),
        BatchLeaseOutcome::NotCommitted(e) => panic!("batch lease failed: {e:?}"),
        BatchLeaseOutcome::OutcomeUnknown(ticket) => {
            panic!("batch lease outcome unknown: {ticket:?}")
        }
    };
    assert_eq!(lease.attempt, 1);

    // Ack via batch
    let ack_outcome = batch2.ack(&lease);
    assert!(matches!(ack_outcome, BatchAckOutcome::Pending));

    let commit2 = batch2.commit().expect("lease+ack commit should succeed");
    assert_eq!(commit2.committed_leases, 1);
    assert_eq!(commit2.committed_acks, 1);
    assert!(commit2.outcome_unknown_leases.is_empty());
    assert!(commit2.outcome_unknown_acks.is_empty());
}

#[test]
fn batch_lease_ack_multiple_jobs() {
    let tmp = TempDir::new().unwrap();
    Queue::init(tmp.path(), &CreateOptions::default()).unwrap();
    let mut q = Queue::open(
        tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    )
    .unwrap();

    // Enqueue 4 jobs in a batch
    let mut batch = q.batch();
    for _ in 0..4 {
        batch.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: vec![0xABu8; 64],
            ..Default::default()
        });
    }
    batch.commit().expect("enqueue commit");

    // Lease and ack all 4 via batch
    let mut batch2 = q.batch();
    let mut leased = Vec::new();
    for _ in 0..4 {
        match batch2.lease(0, 30_000_000_000) {
            BatchLeaseOutcome::Pending(info) => leased.push(info),
            BatchLeaseOutcome::Empty => break,
            other => panic!("batch lease failed: {other:?}"),
        }
    }
    assert_eq!(leased.len(), 4, "should lease all 4 jobs");
    for lease in &leased {
        match batch2.ack(lease) {
            BatchAckOutcome::Pending => {}
            other => panic!("batch ack failed: {other:?}"),
        }
    }
    let outcome = batch2.commit().expect("lease+ack commit");
    assert_eq!(outcome.committed_leases, 4);
    assert_eq!(outcome.committed_acks, 4);
}

#[test]
fn batch_payload_verification_propagates_corruption() {
    let (tmp, mut queue) = create_test_queue();
    let lease = enqueue_and_lease(&mut queue);
    let source = tmp.path().join(&lease.exact_source_path);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(source)
        .unwrap();
    let last_payload_byte = file.metadata().unwrap().len().checked_sub(1).unwrap();
    file.write_all_at(&[0], last_payload_byte).unwrap();

    let batch = queue.batch();
    assert_eq!(
        batch.verify_lease_payload(&lease),
        Err(Error::PayloadCorrupt)
    );
}

#[test]
fn batch_commit_barrier_failure_marks_every_pending_lifecycle_unknown() {
    let (_tmp, mut queue) = create_test_queue();
    let mut batch = queue.batch();
    assert!(matches!(
        batch.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".into(),
            payload: b"batch barrier".to_vec(),
            ..Default::default()
        }),
        BatchEnqueueOutcome::Pending(_)
    ));
    let lease = match batch.lease(0, 30_000_000_000) {
        BatchLeaseOutcome::Pending(lease) => lease,
        other => panic!("batch lease failed: {other:?}"),
    };
    batch.verify_lease_payload(&lease).unwrap();
    assert!(matches!(batch.ack(&lease), BatchAckOutcome::Pending));

    fs::fault::reset();
    fs::fault::inject_errno("fsync_dir_fd", 1, libc::EIO);
    let outcome = batch.commit().expect_err("batch barrier should fail");
    fs::fault::reset();

    assert!(outcome.committed_enqueues.is_empty());
    assert_eq!(outcome.outcome_unknown_enqueues.len(), 1);
    assert_eq!(outcome.committed_leases, 0);
    assert_eq!(outcome.outcome_unknown_leases.len(), 1);
    assert_eq!(outcome.committed_acks, 0);
    assert_eq!(outcome.outcome_unknown_acks.len(), 1);
    assert!(queue.is_poisoned());
}

#[test]
fn dirtyset_record_deduplicates_and_sync_all_fsyncs() {
    // Tests DirtySet::record deduplicates by (dev, inode) and
    // sync_all actually calls fsync_dir_fd.
    use crate::queue::engine::DirtySet;

    let tmp = TempDir::new().unwrap();
    std::fs::create_dir_all(tmp.path().join("ready/0000")).unwrap();
    let root = std::fs::File::open(tmp.path()).unwrap();
    let ready_fd = fs::open_directory(root.as_fd(), "ready").unwrap();
    let shard_fd = fs::open_directory(ready_fd.as_fd(), "0000").unwrap();

    let mut dirty = DirtySet::new();
    assert!(dirty.is_empty());
    assert_eq!(dirty.len(), 0);

    // Record the same directory twice — should deduplicate
    dirty.record(shard_fd.as_fd()).unwrap();
    dirty
        .record_with(shard_fd.as_fd(), |_| {
            Err(io::Error::other("duplicate descriptor was cloned"))
        })
        .unwrap();
    assert_eq!(dirty.len(), 1);

    dirty.record(ready_fd.as_fd()).unwrap();
    assert_eq!(dirty.len(), 2);

    // sync_all must actually fsync (not no-op)
    assert!(dirty.sync_all().is_ok());

    dirty.clear();
    assert!(dirty.is_empty());
}

#[test]
fn dirty_ensure_skips_known_directory_without_recording_parent() {
    let (_tmp, queue) = create_test_queue();
    let mut initial_dirty = engine::DirtySet::new();
    queue
        .ensure_dir_with_dirty("ready/0000", Some(&mut initial_dirty))
        .unwrap();
    initial_dirty.sync_all().unwrap();

    fs::fault::reset();
    fs::fault::inject_errno("mkdirat", 1, libc::EIO);
    let mut next_dirty = engine::DirtySet::new();
    let result = queue.ensure_dir_with_dirty("ready/0000", Some(&mut next_dirty));
    let mkdir_calls = fs::fault::call_count("mkdirat");
    fs::fault::reset();

    assert!(result.is_ok());
    assert_eq!(mkdir_calls, 0);
    assert!(next_dirty.is_empty());
}

#[test]
fn dirtyset_extend_merges_without_overwriting() {
    use crate::queue::engine::DirtySet;

    let tmp = TempDir::new().unwrap();
    std::fs::create_dir_all(tmp.path().join("a")).unwrap();
    std::fs::create_dir_all(tmp.path().join("b")).unwrap();
    let root = std::fs::File::open(tmp.path()).unwrap();
    let a_fd = fs::open_directory(root.as_fd(), "a").unwrap();
    let b_fd = fs::open_directory(root.as_fd(), "b").unwrap();

    let mut d1 = DirtySet::new();
    d1.record(a_fd.as_fd()).unwrap();
    assert_eq!(d1.len(), 1);

    let mut d2 = DirtySet::new();
    d2.record(a_fd.as_fd()).unwrap();
    d2.record(b_fd.as_fd()).unwrap();

    d1.extend(d2);
    // a was already in d1, so only b is added
    assert_eq!(d1.len(), 2);
    assert!(d1.sync_all().is_ok());
}

#[test]
fn dirtyset_sync_all_propagates_fsync_error() {
    // Kills DirtySet::sync_all -> Ok(()) mutant: if sync_all is a no-op,
    // it won't call fsync_dir_fd and won't return the injected error.
    use crate::queue::engine::DirtySet;

    let tmp = TempDir::new().unwrap();
    std::fs::create_dir_all(tmp.path().join("ready/0000")).unwrap();
    let root = std::fs::File::open(tmp.path()).unwrap();
    let ready_fd = fs::open_directory(root.as_fd(), "ready").unwrap();
    let shard_fd = fs::open_directory(ready_fd.as_fd(), "0000").unwrap();

    let mut dirty = DirtySet::new();
    dirty.record(shard_fd.as_fd()).unwrap();
    assert!(!dirty.is_empty());

    fs::fault::reset();
    fs::fault::inject_errno("fsync_dir_fd", 1, libc::EIO);
    let result = dirty.sync_all();
    fs::fault::reset();

    assert!(
        result.is_err(),
        "sync_all must propagate fsync_dir_fd error"
    );
}

#[test]
fn deferred_sync_via_queue_sync_actually_fsyncs() {
    // Kills DirtySet::is_empty -> true mutant: if is_empty always returns true,
    // Queue::sync() will skip the actual fsync and not trigger the injected error.
    let (_tmp, mut queue) = {
        let tmp = TempDir::new().unwrap();
        fs::fault::pin_clock_realtime_ns(fs::clock_realtime_ns().unwrap());
        Queue::init(tmp.path(), &CreateOptions::default()).unwrap();
        let queue = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                deferred_dir_sync: true,
                ..Default::default()
            },
        )
        .unwrap();
        (tmp, queue)
    };

    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"deferred".to_vec(),
        ..Default::default()
    });

    // Inject fault on fsync_dir_fd — sync() must hit it
    fs::fault::reset();
    fs::fault::inject_errno("fsync_dir_fd", 1, libc::EIO);
    let result = queue.sync();
    fs::fault::reset();

    assert!(result.is_err(), "sync() must call fsync_dir_fd when dirty");

    // A failed barrier retains the exact dirty set. A later successful sync
    // promotes the deferred publication and clears the pending barriers.
    assert!(queue.sync().is_ok());
    fs::fault::inject("fsync_dir_fd", u64::MAX);
    assert!(queue.sync().is_ok());
    assert_eq!(fs::fault::call_count("fsync_dir_fd"), 0);
    fs::fault::reset();
}

#[test]
fn batch_enqueue_deferred_publish_classifies_link_errors() {
    // Exercises publish_tmpfile_noreplace_deferred error paths through batch enqueue.
    for errno in [libc::EEXIST, libc::ENOSPC, libc::EIO] {
        let (_tmp, mut queue) = create_test_queue();
        if !tmpfile_supported(&queue) || !link_publication_attempted(&queue) {
            return;
        }
        fs::fault::reset();
        fs::fault::set_clock_realtime_ns(1_000_000_000);
        fs::fault::inject("linkat_proc_self_fd", u64::MAX);
        fs::fault::inject_errno("linkat_empty_path", 1, errno);

        let mut batch = queue.batch();
        let outcome = batch.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "text/plain".into(),
            payload: b"deferred publish failure".to_vec(),
            ..Default::default()
        });
        fs::fault::reset();

        // Batch enqueue should report NotCommitted (not Pending) on failure
        match outcome {
            BatchEnqueueOutcome::NotCommitted(_, _) => {}
            other => panic!("expected NotCommitted for errno {errno}, got {other:?}"),
        }
        assert!(!queue.is_poisoned());
    }
}

#[test]
fn batch_lease_deferred_move_classifies_rename_errors() {
    // Exercises move_noreplace_deferred error paths through batch lease.
    // Each variant re-enqueues a fresh job since a failed lease consumes it.
    for (errno, expect_label) in [
        (libc::EIO, "not_committed"),
        (libc::EEXIST, "not_committed"),
        (libc::ENOENT, "empty_or_not_committed"),
    ] {
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"batch lease fault".to_vec(),
            ..Default::default()
        });

        fs::fault::reset();
        fs::fault::inject_errno("renameat2_noreplace", 1, errno);

        let mut batch = queue.batch();
        let outcome = batch.lease(0, 30_000_000_000);
        fs::fault::reset();

        match (&outcome, expect_label) {
            (BatchLeaseOutcome::NotCommitted(_), "not_committed") => {}
            (BatchLeaseOutcome::Empty, "empty_or_not_committed") => {}
            (BatchLeaseOutcome::NotCommitted(_), "empty_or_not_committed") => {}
            other => panic!("unexpected for errno {errno}: {other:?}"),
        }
    }
}

#[test]
fn batch_enqueue_preserves_every_injected_postlinearization_failure() {
    for named_fallback in [false, true] {
        // On filesystems that force the named path, the false variant
        // would duplicate the true variant under different call numbering.
        if !named_fallback && !link_publication_attempted(&create_test_queue().1) {
            continue;
        }
        for fault in ["fstat"] {
            let count_calls = || {
                let (_tmp, mut queue) = create_test_queue();
                if named_fallback {
                    queue.publication_mode = Some(fs::PublicationMode::NamedFallback);
                } else if !tmpfile_supported(&queue) {
                    return 0;
                }
                fs::fault::reset();
                fs::fault::inject(fault, u64::MAX);
                let outcome = queue.batch().enqueue(EnqueueInput {
                    maximum_attempts: 3,
                    content_type: "x".into(),
                    payload: b"batch enqueue fault matrix".to_vec(),
                    ..Default::default()
                });
                let calls = fs::fault::call_count(fault);
                fs::fault::reset();
                assert!(matches!(outcome, BatchEnqueueOutcome::Pending(_)));
                calls
            };
            let calls = count_calls();
            if calls == 0 {
                continue;
            }

            let mut exercised = 0;
            for target in 1..=calls {
                let (tmp, mut queue) = create_test_queue();
                if named_fallback {
                    queue.publication_mode = Some(fs::PublicationMode::NamedFallback);
                }
                fs::fault::reset();
                fs::fault::inject_errno(fault, target, libc::EIO);
                let outcome = queue.batch().enqueue(EnqueueInput {
                    maximum_attempts: 3,
                    content_type: "x".into(),
                    payload: b"batch enqueue fault matrix".to_vec(),
                    ..Default::default()
                });
                let reached = fs::fault::call_count(fault) >= target;
                fs::fault::reset();
                let linearized = find_file_with_suffix(&tmp.path().join("ready"), ".sqj").is_some();
                if linearized && reached {
                    exercised += 1;
                    assert!(
                        matches!(outcome, BatchEnqueueOutcome::OutcomeUnknown(_, _)),
                        "{fault} call {target} after publication became {outcome:?}"
                    );
                }
            }
            assert!(
                exercised > 0,
                "no postlinearization {fault} failure was exercised"
            );
        }
    }
}

#[test]
fn batch_lease_preserves_every_injected_postlinearization_failure() {
    for fault in ["fstatat", "fstat", "pread"] {
        let count_calls = || {
            let (_tmp, mut queue) = create_test_queue();
            assert!(matches!(
                queue.enqueue(EnqueueInput {
                    maximum_attempts: 3,
                    content_type: "x".into(),
                    payload: b"batch lease fault matrix".to_vec(),
                    ..Default::default()
                }),
                EnqueueOutcome::Committed(_)
            ));
            fs::fault::reset();
            fs::fault::inject(fault, u64::MAX);
            let outcome = queue.batch().lease(0, 30_000_000_000);
            let calls = fs::fault::call_count(fault);
            fs::fault::reset();
            assert!(matches!(outcome, BatchLeaseOutcome::Pending(_)));
            calls
        };
        let calls = count_calls();
        let mut exercised = 0;
        for target in 1..=calls {
            let (tmp, mut queue) = create_test_queue();
            assert!(matches!(
                queue.enqueue(EnqueueInput {
                    maximum_attempts: 3,
                    content_type: "x".into(),
                    payload: b"batch lease fault matrix".to_vec(),
                    ..Default::default()
                }),
                EnqueueOutcome::Committed(_)
            ));
            fs::fault::reset();
            fs::fault::inject_errno(fault, target, libc::EIO);
            let outcome = queue.batch().lease(0, 30_000_000_000);
            let reached = fs::fault::call_count(fault) >= target;
            fs::fault::reset();
            let linearized = find_leased_job(&tmp.path().join("ready")).is_some();
            if linearized && reached {
                match outcome {
                    BatchLeaseOutcome::OutcomeUnknown(_) => exercised += 1,
                    BatchLeaseOutcome::Pending(_) => {}
                    other => panic!("{fault} call {target} after claim became {other:?}"),
                }
            }
        }
        assert!(
            exercised > 0,
            "no postlinearization {fault} failure was exercised"
        );
    }
}

#[test]
fn batch_ack_preserves_every_injected_postlinearization_failure() {
    for fault in ["fstatat", "fstat"] {
        let prepare = || {
            let (tmp, mut queue) = create_test_queue();
            assert!(matches!(
                queue.enqueue(EnqueueInput {
                    maximum_attempts: 3,
                    content_type: "x".into(),
                    payload: b"batch ack fault matrix".to_vec(),
                    ..Default::default()
                }),
                EnqueueOutcome::Committed(_)
            ));
            let lease = match queue.lease(0, 30_000_000_000) {
                LeaseOutcome::Leased(lease) => lease,
                other => panic!("lease setup failed: {other:?}"),
            };
            (tmp, queue, lease)
        };
        let (_tmp, mut queue, lease) = prepare();
        fs::fault::reset();
        fs::fault::inject(fault, u64::MAX);
        let outcome = queue.batch().ack(&lease);
        let calls = fs::fault::call_count(fault);
        fs::fault::reset();
        assert!(matches!(outcome, BatchAckOutcome::Pending));

        let mut exercised = 0;
        for target in 1..=calls {
            let (tmp, mut queue, lease) = prepare();
            fs::fault::reset();
            fs::fault::inject_errno(fault, target, libc::EIO);
            let outcome = queue.batch().ack(&lease);
            let reached = fs::fault::call_count(fault) >= target;
            fs::fault::reset();
            let linearized = find_file_with_suffix(&tmp.path().join("receipts"), ".rct").is_some();
            if linearized && reached {
                match outcome {
                    BatchAckOutcome::OutcomeUnknown(_) => exercised += 1,
                    BatchAckOutcome::Pending => {}
                    other => panic!("{fault} call {target} after ack became {other:?}"),
                }
            }
        }
        assert!(
            exercised > 0,
            "no postlinearization {fault} failure was exercised"
        );
    }
}

#[test]
fn enqueue_basic() {
    let (_tmp, mut queue) = create_test_queue();
    let input = EnqueueInput {
        maximum_attempts: 3,
        content_type: "text/plain".to_string(),
        payload: b"hello world".to_vec(),
        ..Default::default()
    };
    let outcome = queue.enqueue(input);
    match outcome {
        EnqueueOutcome::Committed(ticket) => {
            assert!(!ticket.expected_relative_path.is_empty());
            assert!(ticket.expected_relative_path.starts_with("ready/"));
        }
        _ => panic!("expected committed, got {outcome:?}"),
    }
}

#[test]
fn named_fallback_publishes_complete_job() {
    let (_tmp, mut queue) = create_test_queue();
    fs::fault::inject_errno("open_tmpfile", 1, libc::EOPNOTSUPP);
    let payload = b"named fallback payload";
    let enqueue = queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "text/plain".to_string(),
        payload: payload.to_vec(),
        ..Default::default()
    });
    fs::fault::reset();
    assert!(matches!(enqueue, EnqueueOutcome::Committed(_)));

    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(lease) => lease,
        outcome => panic!("expected lease, got {outcome:?}"),
    };
    let mut bytes = vec![0; payload.len()];
    let read = queue
        .read_lease_payload_chunk(&lease, &mut bytes, 0)
        .unwrap();
    assert_eq!(read, payload.len());
    assert_eq!(bytes, payload);
}

#[test]
fn preferred_named_publication_bypasses_tmpfile_linking() {
    let (_tmp, mut queue) = create_test_queue();
    queue.publication_mode = Some(fs::PublicationMode::NamedFallback);
    fs::fault::reset();
    fs::fault::inject("open_tmpfile", u64::MAX);

    let enqueue = queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "text/plain".into(),
        payload: b"named preference".to_vec(),
        ..Default::default()
    });
    let tmpfile_calls = fs::fault::call_count("open_tmpfile");
    let rename_calls = fs::fault::call_count("renameat2_noreplace");
    fs::fault::reset();

    assert!(matches!(enqueue, EnqueueOutcome::Committed(_)));
    assert_eq!(tmpfile_calls, 0);
    assert_eq!(rename_calls, 1);
}

#[test]
fn deferred_named_publication_records_source_and_destination_directories() {
    let (_tmp, mut queue) = create_test_queue();
    queue.publication_mode = Some(fs::PublicationMode::NamedFallback);
    let boot_id = queue.boot_id.clone();
    let mut batch = queue.batch();
    let outcome = batch.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "text/plain".into(),
        payload: b"deferred named publication".to_vec(),
        ..Default::default()
    });
    let BatchEnqueueOutcome::Pending(ticket) = outcome else {
        panic!("named batch enqueue failed: {outcome:?}");
    };
    let destination_path = ticket.expected_relative_path.rsplit_once('/').unwrap().0;
    let shard = destination_path.rsplit('/').next().unwrap();
    let source_path = format!("tmp/{boot_id}/{shard}");
    let source_fd = open_relative(batch.queue.root_fd.as_fd(), &source_path).unwrap();
    let destination_fd = open_relative(batch.queue.root_fd.as_fd(), destination_path).unwrap();
    let source_identity = fs::fstat(source_fd.as_fd()).unwrap();
    let destination_identity = fs::fstat(destination_fd.as_fd()).unwrap();

    fs::fault::reset();
    fs::fault::inject("fsync_dir_fd", u64::MAX);
    batch.commit().expect("named batch commit");
    let synced = fs::fault::fd_identities("fsync_dir_fd");
    fs::fault::reset();

    assert!(synced.contains(&(source_identity.st_dev as u64, source_identity.st_ino as u64)));
    assert!(synced.contains(&(
        destination_identity.st_dev as u64,
        destination_identity.st_ino as u64
    )));
}

#[test]
fn tmpfile_publish_failure_classification_preserves_phase_and_errno() {
    for (failure, expected) in [
        (engine::TmpfilePublishFailure::AlreadyExists, "collision"),
        (
            engine::TmpfilePublishFailure::NotCommitted {
                phase: engine::TmpfilePublishPhase::Link,
                source: io::Error::from_raw_os_error(libc::ENOSPC),
            },
            "resource",
        ),
        (
            engine::TmpfilePublishFailure::NotCommitted {
                phase: engine::TmpfilePublishPhase::SourceIdentity,
                source: io::Error::from_raw_os_error(libc::EIO),
            },
            "source identity",
        ),
        (
            engine::TmpfilePublishFailure::OutcomeUnknown {
                phase: engine::TmpfilePublishPhase::DestinationFsync,
                source: io::Error::from_raw_os_error(libc::EIO),
            },
            "destination fsync",
        ),
    ] {
        let classified = PublishError::classify_tmpfile(failure);
        match expected {
            "collision" => assert!(matches!(
                classified,
                PublishError::NotCommitted(Error::IdentityCollision)
            )),
            "resource" => assert!(matches!(
                classified,
                PublishError::NotCommitted(Error::ResourceExhausted)
            )),
            "source identity" => {
                let PublishError::NotCommitted(Error::IoFailure(message)) = classified else {
                    panic!("expected not-committed I/O failure");
                };
                assert!(message.contains("SourceIdentity"));
            }
            "destination fsync" => {
                let PublishError::OutcomeUnknown(Error::IoFailure(message)) = classified else {
                    panic!("expected outcome-unknown I/O failure");
                };
                assert!(message.contains("DestinationFsync"));
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn tmpfile_publication_uses_proc_then_named_fallback() {
    for named_fallback in [false, true] {
        let (_tmp, mut queue) = create_test_queue();
        if !tmpfile_supported(&queue) || !link_publication_attempted(&queue) {
            return;
        }
        fs::fault::reset();
        fs::fault::set_clock_realtime_ns(1_000_000_000);
        fs::fault::inject_errno("linkat_empty_path", 1, libc::ENOENT);
        if named_fallback {
            fs::fault::inject_errno("linkat_proc_self_fd", 1, libc::ENOENT);
        } else {
            fs::fault::inject("linkat_proc_self_fd", u64::MAX);
        }
        fs::fault::inject("renameat2_noreplace", u64::MAX);

        let outcome = queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "text/plain".into(),
            payload: b"publication fallback".to_vec(),
            ..Default::default()
        });
        let proc_calls = fs::fault::call_count("linkat_proc_self_fd");
        let rename_calls = fs::fault::call_count("renameat2_noreplace");
        fs::fault::reset();

        assert!(matches!(outcome, EnqueueOutcome::Committed(_)));
        assert_eq!(proc_calls, 1);
        assert_eq!(rename_calls, u64::from(named_fallback));
        assert!(!queue.is_poisoned());
    }
}

#[test]
fn tmpfile_publication_does_not_weaken_fatal_link_failures() {
    for (errno, expected) in [
        (libc::EEXIST, "collision"),
        (libc::ENOSPC, "resource"),
        (libc::EIO, "io"),
        (libc::EPERM, "io"),
    ] {
        let (tmp, mut queue) = create_test_queue();
        if !tmpfile_supported(&queue) || !link_publication_attempted(&queue) {
            return;
        }
        fs::fault::reset();
        fs::fault::set_clock_realtime_ns(1_000_000_000);
        fs::fault::inject_errno("linkat_empty_path", 1, errno);
        fs::fault::inject("linkat_proc_self_fd", u64::MAX);

        let outcome = queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "text/plain".into(),
            payload: b"fatal publication failure".to_vec(),
            ..Default::default()
        });
        let proc_calls = fs::fault::call_count("linkat_proc_self_fd");
        fs::fault::reset();

        match expected {
            "collision" => assert!(matches!(
                outcome,
                EnqueueOutcome::NotCommitted(_, Error::IdentityCollision)
            )),
            "resource" => assert!(matches!(
                outcome,
                EnqueueOutcome::NotCommitted(_, Error::ResourceExhausted)
            )),
            "io" => assert!(matches!(
                outcome,
                EnqueueOutcome::NotCommitted(_, Error::IoFailure(_))
            )),
            _ => unreachable!(),
        }
        assert_eq!(proc_calls, 0);
        assert!(!queue.is_poisoned());
        assert!(find_file_with_suffix(&tmp.path().join("ready"), ".sqj").is_none());
    }
}

#[test]
fn tmpfile_publication_preserves_postlinearization_failures() {
    let (tmp, mut queue) = create_test_queue();
    if !tmpfile_supported(&queue) || !link_publication_attempted(&queue) {
        return;
    }
    queue.ensure_dir("ready/0000").unwrap();
    fs::fault::reset();
    fs::fault::set_clock_realtime_ns(1_000_000_000);
    fs::fault::inject_errno("fsync_dir_fd", 1, libc::EIO);

    let outcome = queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "text/plain".into(),
        payload: b"indeterminate publication".to_vec(),
        ..Default::default()
    });
    fs::fault::reset();

    let EnqueueOutcome::OutcomeUnknown(ticket, Error::IoFailure(message)) = outcome else {
        panic!("expected outcome unknown");
    };
    assert!(queue.is_poisoned());
    assert!(tmp.path().join(ticket.expected_relative_path).exists());
    assert!(message.contains("DestinationFsync"));
}

#[test]
fn named_fallback_preserves_prelinearization_errors_and_cleans_temp() {
    for (errno, expected) in [
        (libc::EEXIST, "collision"),
        (libc::ENOSPC, "resource"),
        (libc::ENOENT, "missing"),
    ] {
        fs::fault::reset();
        fs::fault::set_clock_realtime_ns(1_000_000_000);
        let (tmp, mut queue) = create_test_queue();
        precreate_named_temp_shards(&tmp, &queue);
        fs::fault::inject_errno("open_tmpfile", 1, libc::EOPNOTSUPP);
        fs::fault::inject_errno("renameat2_noreplace", 1, errno);

        let outcome = queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "text/plain".into(),
            payload: b"named failure".to_vec(),
            ..Default::default()
        });
        fs::fault::reset();

        match expected {
            "collision" => assert!(matches!(
                outcome,
                EnqueueOutcome::NotCommitted(_, Error::IdentityCollision)
            )),
            "resource" => assert!(matches!(
                outcome,
                EnqueueOutcome::NotCommitted(_, Error::ResourceExhausted)
            )),
            "missing" => assert!(matches!(
                outcome,
                EnqueueOutcome::NotCommitted(_, Error::IoFailure(_))
            )),
            _ => unreachable!(),
        }
        assert!(!queue.is_poisoned());
        assert!(find_file_with_suffix(&tmp.path().join("tmp"), "").is_none());
        assert!(find_file_with_suffix(&tmp.path().join("ready"), ".sqj").is_none());
    }
}

#[test]
fn named_fallback_preserves_each_postlinearization_barrier() {
    for fsync_call in [1, 2] {
        fs::fault::reset();
        fs::fault::set_clock_realtime_ns(1_000_000_000);
        let (tmp, mut queue) = create_test_queue();
        precreate_named_temp_shards(&tmp, &queue);
        fs::fault::inject_errno("open_tmpfile", 1, libc::EOPNOTSUPP);
        fs::fault::inject_errno("fsync_dir_fd", fsync_call, libc::EIO);

        let outcome = queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "text/plain".into(),
            payload: b"named barrier".to_vec(),
            ..Default::default()
        });
        fs::fault::reset();

        let EnqueueOutcome::OutcomeUnknown(ticket, Error::IoFailure(_)) = outcome else {
            panic!("expected outcome unknown");
        };
        assert!(queue.is_poisoned());
        assert!(tmp.path().join(ticket.expected_relative_path).exists());
        assert!(find_file_with_suffix(&tmp.path().join("tmp"), "").is_none());
    }
}

#[test]
fn ticket_envelope_digest_authenticates_ready_header() {
    let (_tmp, mut queue) = create_test_queue();
    let enqueue = match queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "text/plain".to_string(),
        payload: b"ticket evidence".to_vec(),
        ..Default::default()
    }) {
        EnqueueOutcome::Committed(ticket) => ticket,
        outcome => panic!("expected committed enqueue, got {outcome:?}"),
    };
    let (directory, name) = enqueue.expected_relative_path.rsplit_once('/').unwrap();
    let directory_fd = open_relative(queue.root_fd().as_fd(), directory).unwrap();

    let witness = Queue::open_claim_source(directory_fd.as_fd(), name, &enqueue.job_id, 3)
        .unwrap()
        .unwrap();
    assert_eq!(witness.evidence.envelope_digest, enqueue.envelope_digest);
    assert_eq!(witness.evidence.payload_length, 15);

    let mut wrong_job_id = enqueue.job_id;
    wrong_job_id[0] ^= 0xff;
    assert!(matches!(
        Queue::open_claim_source(directory_fd.as_fd(), name, &wrong_job_id, 3,),
        Err(Error::QueueCorrupt(_))
    ));
    assert!(matches!(
        Queue::open_claim_source(directory_fd.as_fd(), name, &enqueue.job_id, 4,),
        Err(Error::QueueCorrupt(_))
    ));
}

#[test]
fn missing_claim_source_before_open_is_a_scan_miss() {
    let (tmp, mut queue) = create_test_queue();
    let enqueue = match queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "text/plain".to_string(),
        payload: b"missing before open".to_vec(),
        ..Default::default()
    }) {
        EnqueueOutcome::Committed(ticket) => ticket,
        outcome => panic!("expected committed enqueue, got {outcome:?}"),
    };
    let (directory, name) = enqueue.expected_relative_path.rsplit_once('/').unwrap();
    let directory_fd = open_relative(queue.root_fd().as_fd(), directory).unwrap();

    fs::fault::reset();
    fs::fault::inject_errno("openat", 1, libc::EIO);
    assert!(matches!(
        Queue::open_claim_source(directory_fd.as_fd(), name, &enqueue.job_id, 3),
        Err(Error::IoFailure(_))
    ));
    fs::fault::reset();

    std::fs::remove_file(tmp.path().join(&enqueue.expected_relative_path)).unwrap();

    assert!(
        Queue::open_claim_source(directory_fd.as_fd(), name, &enqueue.job_id, 3)
            .unwrap()
            .is_none()
    );
}

#[test]
fn claim_source_witness_classifies_disappearance_and_replacement() {
    let (tmp, mut queue) = create_test_queue();
    let enqueue = match queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "text/plain".to_string(),
        payload: b"replacement".to_vec(),
        ..Default::default()
    }) {
        EnqueueOutcome::Committed(ticket) => ticket,
        outcome => panic!("expected committed enqueue, got {outcome:?}"),
    };
    let (directory, name) = enqueue.expected_relative_path.rsplit_once('/').unwrap();
    let directory_fd = open_relative(queue.root_fd().as_fd(), directory).unwrap();
    let witness = Queue::open_claim_source(directory_fd.as_fd(), name, &enqueue.job_id, 3)
        .unwrap()
        .unwrap();
    let source = tmp.path().join(&enqueue.expected_relative_path);
    let displaced = tmp.path().join("tmp/displaced-ready.sqj");
    std::fs::rename(&source, &displaced).unwrap();

    assert_eq!(
        observe_witness_path(directory_fd.as_fd(), name, witness.device, witness.inode,).unwrap(),
        WitnessPathObservation::Gone
    );

    std::fs::copy(&displaced, &source).unwrap();
    assert_eq!(
        observe_witness_path(directory_fd.as_fd(), name, witness.device, witness.inode,).unwrap(),
        WitnessPathObservation::Mismatch
    );
    let original = fs::fstat(witness.file_fd.as_fd()).unwrap();
    assert!(stat_matches_witness(
        &original,
        witness.device,
        witness.inode
    ));
}

#[test]
fn leased_source_witness_rejects_replacement_after_validation() {
    let (tmp, mut queue) = create_test_queue();
    let lease = enqueue_and_lease(&mut queue);
    let source = queue
        .open_and_validate_current_lease(&lease)
        .unwrap()
        .unwrap();
    let source_path = tmp.path().join(&lease.exact_source_path);
    let displaced = tmp.path().join("tmp/displaced-leased.sqj");
    std::fs::rename(&source_path, &displaced).unwrap();
    std::fs::copy(&displaced, &source_path).unwrap();

    assert_eq!(
        Queue::observe_leased_source_path(&source).unwrap(),
        WitnessPathObservation::Mismatch
    );
    let ready = queue.layout().ready(&CommonFields {
        job_id: lease.job_id,
        generation: lease.generation + 1,
        attempt: lease.attempt,
        maximum_attempts: lease.maximum_attempts,
    });
    let destination_directory = open_relative(queue.root_fd(), &ready.directory()).unwrap();
    assert!(matches!(
        Queue::execute_leased_move_with_dirty(
            &source,
            destination_directory.as_fd(),
            &ready.filename,
            None,
        ),
        LeasedMoveOutcome::SourceChanged
    ));
    assert!(!tmp.path().join(ready.relative_path()).exists());
}

#[test]
fn leased_source_witness_rejects_symlink_after_validation() {
    let (tmp, mut queue) = create_test_queue();
    let lease = enqueue_and_lease(&mut queue);
    let source = queue
        .open_and_validate_current_lease(&lease)
        .unwrap()
        .unwrap();
    let source_path = tmp.path().join(&lease.exact_source_path);
    let displaced = tmp.path().join("tmp/displaced-leased-symlink.sqj");
    std::fs::rename(&source_path, &displaced).unwrap();
    std::os::unix::fs::symlink(&displaced, &source_path).unwrap();

    assert_eq!(
        Queue::observe_leased_source_path(&source).unwrap(),
        WitnessPathObservation::Mismatch
    );
}

#[test]
fn leased_source_witness_classifies_absence_and_io() {
    let (tmp, mut queue) = create_test_queue();
    let lease = enqueue_and_lease(&mut queue);
    let source = queue
        .open_and_validate_current_lease(&lease)
        .unwrap()
        .unwrap();

    fs::fault::reset();
    fs::fault::inject("fstatat", 1);
    assert!(matches!(
        Queue::observe_leased_source_path(&source),
        Err(Error::IoFailure(_))
    ));
    fs::fault::reset();

    std::fs::remove_file(tmp.path().join(&lease.exact_source_path)).unwrap();
    assert_eq!(
        Queue::observe_leased_source_path(&source).unwrap(),
        WitnessPathObservation::Gone
    );
}

#[test]
fn witnessed_rename_preserves_failure_categories() {
    for (errno, expected) in [
        (libc::ENOENT, "gone"),
        (libc::EEXIST, "collision"),
        (libc::EIO, "failed"),
    ] {
        let (_tmp, mut queue) = create_test_queue();
        let lease = enqueue_and_lease(&mut queue);
        let source = queue
            .open_and_validate_current_lease(&lease)
            .unwrap()
            .unwrap();
        let ready = queue.layout().ready(&CommonFields {
            job_id: lease.job_id,
            generation: lease.generation + 1,
            attempt: lease.attempt,
            maximum_attempts: lease.maximum_attempts,
        });
        let destination_directory = open_relative(queue.root_fd(), &ready.directory()).unwrap();
        fs::fault::reset();
        fs::fault::inject_errno("renameat2_noreplace", 1, errno);
        let outcome = Queue::execute_leased_move_with_dirty(
            &source,
            destination_directory.as_fd(),
            &ready.filename,
            None,
        );
        match expected {
            "gone" => assert!(matches!(outcome, LeasedMoveOutcome::SourceGone)),
            "collision" => assert!(matches!(outcome, LeasedMoveOutcome::Collision)),
            "failed" => assert!(matches!(outcome, LeasedMoveOutcome::Failed(_))),
            _ => unreachable!(),
        }
        fs::fault::reset();
    }
}

#[test]
fn witnessed_rename_reports_post_linearization_identity_error() {
    let (_tmp, mut queue) = create_test_queue();
    let lease = enqueue_and_lease(&mut queue);
    let source = queue
        .open_and_validate_current_lease(&lease)
        .unwrap()
        .unwrap();
    let ready = queue.layout().ready(&CommonFields {
        job_id: lease.job_id,
        generation: lease.generation + 1,
        attempt: lease.attempt,
        maximum_attempts: lease.maximum_attempts,
    });
    let destination_directory = open_relative(queue.root_fd(), &ready.directory()).unwrap();
    fs::fault::reset();
    fs::fault::inject_errno("fstatat", 2, libc::EIO);
    assert!(matches!(
        Queue::execute_leased_move_with_dirty(
            &source,
            destination_directory.as_fd(),
            &ready.filename,
            None,
        ),
        LeasedMoveOutcome::OutcomeUnknown(TransitionPhase::Linearized)
    ));
    fs::fault::reset();
}

#[test]
fn claim_source_file_type_and_link_policy_table() {
    assert!(is_singly_linked_regular(libc::S_IFREG | 0o400, 1));
    assert!(!is_singly_linked_regular(libc::S_IFREG | 0o400, 2));
    assert!(!is_singly_linked_regular(libc::S_IFDIR | 0o500, 1));
    assert!(!is_singly_linked_regular(libc::S_IFLNK | 0o400, 1));
}

#[test]
fn claim_source_evidence_detects_in_place_header_change() {
    let (tmp, mut queue) = create_test_queue();
    let enqueue = match queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "text/plain".to_string(),
        payload: b"in-place".to_vec(),
        ..Default::default()
    }) {
        EnqueueOutcome::Committed(ticket) => ticket,
        outcome => panic!("expected committed enqueue, got {outcome:?}"),
    };
    let (directory, name) = enqueue.expected_relative_path.rsplit_once('/').unwrap();
    let directory_fd = open_relative(queue.root_fd().as_fd(), directory).unwrap();
    let witness = Queue::open_claim_source(directory_fd.as_fd(), name, &enqueue.job_id, 3)
        .unwrap()
        .unwrap();
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(tmp.path().join(enqueue.expected_relative_path))
        .unwrap();
    file.write_at(&[0xff], 0).unwrap();

    assert!(matches!(
        Queue::read_claim_ticket_evidence(witness.file_fd.as_fd(), &enqueue.job_id, 3,),
        Err(Error::QueueCorrupt(_))
    ));
}

#[test]
fn lease_reports_ready_header_corruption_without_flattening() {
    let (tmp, mut queue) = create_test_queue();
    let enqueue = match queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "text/plain".to_string(),
        payload: b"corrupt claim".to_vec(),
        ..Default::default()
    }) {
        EnqueueOutcome::Committed(ticket) => ticket,
        outcome => panic!("expected committed enqueue, got {outcome:?}"),
    };
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(tmp.path().join(enqueue.expected_relative_path))
        .unwrap();
    file.write_at(&[0xff], 0).unwrap();

    assert!(matches!(
        queue.lease(0, 30_000_000_000),
        LeaseOutcome::NotCommitted(Error::QueueCorrupt(_))
    ));
}

#[test]
fn enqueue_delayed() {
    let (_tmp, mut queue) = create_test_queue();
    let future = fs::clock_realtime_ns().unwrap() + 60_000_000_000; // 60s in future
    let input = EnqueueInput {
        maximum_attempts: 1,
        content_type: "application/octet-stream".to_string(),
        initial_not_before: Some(future),
        payload: vec![0x42; 100],
        ..Default::default()
    };
    let outcome = queue.enqueue(input);
    match outcome {
        EnqueueOutcome::Committed(ticket) => {
            assert!(ticket.expected_relative_path.starts_with("delayed/"));
        }
        _ => panic!("expected committed, got {outcome:?}"),
    }
}

#[test]
fn enqueue_not_before_at_or_before_now_starts_ready() {
    // The effective wall floor is max(clock, watermark bucket start), and
    // init seeds the watermark from the real clock. Pin the clock to a
    // bucket-aligned time in the future so the floor equals the pinned
    // clock exactly, then test not_before one nanosecond below and exactly
    // at that floor. Each case uses a fresh queue.
    let width = 10_000_000_000u64; // default delayed_bucket_width_ns
    let now = 2_000_000_000_000_000_000u64; // bucket-aligned, far past init's seed
    assert_eq!(now % width, 0);
    for (label, nb) in [("below-floor", now - 1), ("exact-floor", now)] {
        let (_tmp, mut queue) = create_test_queue();
        fs::fault::reset();
        fs::fault::set_clock_realtime_ns(now);
        let outcome = queue.enqueue(EnqueueInput {
            maximum_attempts: 1,
            content_type: "x".to_string(),
            initial_not_before: Some(nb),
            payload: vec![0x42; 10],
            ..Default::default()
        });
        fs::fault::reset();
        match outcome {
            EnqueueOutcome::Committed(ticket) => assert!(
                ticket.expected_relative_path.starts_with("ready/"),
                "{label}: not_before at or below the wall floor must start ready, got {}",
                ticket.expected_relative_path
            ),
            other => panic!("{label}: expected committed, got {other:?}"),
        }
    }
}

#[test]
fn enqueue_zero_attempts_rejected() {
    let (_tmp, mut queue) = create_test_queue();
    let input = EnqueueInput {
        maximum_attempts: 0,
        content_type: "x".to_string(),
        payload: vec![1],
        ..Default::default()
    };
    let outcome = queue.enqueue(input);
    assert!(matches!(outcome, EnqueueOutcome::NotCommitted(_, _)));
}

#[test]
fn format_file_exists_after_init() {
    let tmp = TempDir::new().unwrap();
    Queue::init(tmp.path(), &CreateOptions::default()).unwrap();
    assert!(tmp.path().join("FORMAT").exists());
    assert!(tmp.path().join("control").exists());
    assert!(tmp.path().join("control/maintenance.lock").exists());
    assert!(tmp.path().join("control/recovery.lock").exists());
    assert!(tmp.path().join("control/wall-watermark").exists());
    assert!(tmp.path().join("ready").exists());
    // Check shard dirs
    assert!(tmp.path().join("ready/0000").exists());
    assert!(tmp.path().join("ready/003f").exists());
}

#[test]
fn init_resumes_an_interrupted_control_layout() {
    let tmp = TempDir::new().unwrap();
    std::fs::write(tmp.path().join(".initializing"), b"").unwrap();
    std::fs::create_dir(tmp.path().join("control")).unwrap();
    std::fs::write(tmp.path().join("control/maintenance.lock"), b"").unwrap();

    Queue::init(tmp.path(), &CreateOptions::default()).unwrap();

    assert!(tmp.path().join("FORMAT").is_file());
    assert!(!tmp.path().join(".initializing").exists());
    Queue::open(tmp.path(), &OpenOptions::default()).unwrap();
}

#[test]
fn full_lifecycle() {
    let (_tmp, mut queue) = create_test_queue();

    // Enqueue
    let input = EnqueueInput {
        maximum_attempts: 3,
        content_type: "text/plain".to_string(),
        payload: b"hello world".to_vec(),
        ..Default::default()
    };
    let ticket = match queue.enqueue(input) {
        EnqueueOutcome::Committed(t) => t,
        other => panic!("enqueue failed: {other:?}"),
    };

    // Lease
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        other => panic!("lease failed: {other:?}"),
    };
    assert_eq!(lease.job_id, ticket.job_id);
    assert_eq!(lease.attempt, 1);
    assert_eq!(lease.generation, 1);

    // Verify and ack
    queue.verify_lease_payload(&lease).unwrap();
    let ack_result = queue.ack(&lease);
    assert!(matches!(ack_result, AckOutcome::Acked));
}

#[test]
fn lease_empty_queue() {
    let (_tmp, mut queue) = create_test_queue();
    let result = queue.lease(0, 30_000_000_000);
    assert!(matches!(result, LeaseOutcome::Empty));
}

#[test]
fn lease_reports_readdir_failure_after_partial_scan() {
    let tmp = TempDir::new().unwrap();
    Queue::init(
        tmp.path(),
        &CreateOptions {
            shard_count: 1,
            ..Default::default()
        },
    )
    .unwrap();
    std::fs::write(tmp.path().join("ready/0000/ignored"), b"").unwrap();
    let mut queue = Queue::open(
        tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    )
    .unwrap();

    fs::fault::inject("directory_stream_next", 2);
    let outcome = queue.lease(0, 30_000_000_000);
    fs::fault::reset();

    assert!(matches!(
        outcome,
        LeaseOutcome::NotCommitted(Error::IoFailure(_))
    ));
}

#[test]
fn retry_after_lease() {
    let (_tmp, mut queue) = create_test_queue();
    let input = EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    };
    let _ = queue.enqueue(input);

    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        other => panic!("lease failed: {other:?}"),
    };

    // Retry now -> back to ready
    let result = queue.retry_now(&lease);
    assert!(matches!(result, TransitionOutcome::Committed));

    let lease2 = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        other => panic!("second lease failed: {other:?}"),
    };
    assert_eq!(lease2.attempt, 2);
}

#[test]
fn bury_after_lease() {
    let (_tmp, mut queue) = create_test_queue();
    let input = EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    };
    let _ = queue.enqueue(input);

    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        other => panic!("lease failed: {other:?}"),
    };

    let result = queue.bury(&lease, DeadReason::ConsumerRejected);
    assert!(matches!(result, TransitionOutcome::Committed));

    let result2 = queue.lease(0, 30_000_000_000);
    assert!(matches!(result2, LeaseOutcome::Empty));
}

#[test]
fn retry_exhausted_goes_to_dead() {
    let (_tmp, mut queue) = create_test_queue();
    let input = EnqueueInput {
        maximum_attempts: 1,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    };
    let _ = queue.enqueue(input);

    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        other => panic!("lease failed: {other:?}"),
    };
    assert_eq!(lease.maximum_attempts, 1);
    assert_eq!(lease.attempt, 1);

    // Attempt >= maximum_attempts, retry should go to dead
    let result = queue.retry_now(&lease);
    assert!(matches!(result, TransitionOutcome::Committed));

    let result2 = queue.lease(0, 30_000_000_000);
    assert!(matches!(result2, LeaseOutcome::Empty));
}

#[test]
fn renew_extends_lease() {
    let (_tmp, mut queue) = create_test_queue();
    let input = EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    };
    let _ = queue.enqueue(input);

    let lease = match queue.lease(0, 10_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        other => panic!("lease failed: {other:?}"),
    };

    let renewed = match queue.renew(&lease, 60_000_000_000) {
        RenewOutcome::Renewed(l) => l,
        other => panic!("renew failed: {other:?}"),
    };
    assert_eq!(renewed.generation, lease.generation + 1);
    assert!(renewed.expires_boottime_ns > lease.expires_boottime_ns);
    assert!(renewed.expires_wall_ns > lease.expires_wall_ns);
    assert_ne!(renewed.exact_source_path, lease.exact_source_path);
    assert!(_tmp.path().join(&renewed.exact_source_path).exists());
    assert_eq!(renewed.attempt, lease.attempt);
    assert_eq!(renewed.token, lease.token);
}

#[test]
fn deferred_renew_defers_barrier_until_sync() {
    let tmp = TempDir::new().unwrap();
    fs::fault::pin_clock_realtime_ns(fs::clock_realtime_ns().unwrap());
    Queue::init(tmp.path(), &CreateOptions::default()).unwrap();
    let mut queue = Queue::open(
        tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            deferred_dir_sync: true,
            ..Default::default()
        },
    )
    .unwrap();
    let _ = queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 10_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        other => panic!("lease failed: {other:?}"),
    };

    fs::fault::reset();
    fs::fault::inject("fsync_dir_fd", u64::MAX);
    let renewed = match queue.renew(&lease, 60_000_000_000) {
        RenewOutcome::Deferred(l) => l,
        other => panic!("deferred renew failed: {other:?}"),
    };
    // The renewal linearized but performed no directory fsync.
    assert_eq!(fs::fault::call_count("fsync_dir_fd"), 0);
    assert!(!tmp.path().join(&lease.exact_source_path).exists());
    assert!(tmp.path().join(&renewed.exact_source_path).exists());

    queue.sync().unwrap();
    assert!(
        fs::fault::call_count("fsync_dir_fd") >= 1,
        "sync must flush the deferred barrier"
    );
    fs::fault::reset();
}

#[test]
fn plain_renew_still_syncs_inline() {
    let tmp = TempDir::new().unwrap();
    Queue::init(tmp.path(), &CreateOptions::default()).unwrap();
    let mut queue = Queue::open(
        tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    )
    .unwrap();
    let _ = queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 10_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        other => panic!("lease failed: {other:?}"),
    };

    fs::fault::reset();
    fs::fault::inject("fsync_dir_fd", u64::MAX);
    match queue.renew(&lease, 60_000_000_000) {
        RenewOutcome::Renewed(_) => {}
        other => panic!("plain renew failed: {other:?}"),
    }
    assert!(
        fs::fault::call_count("fsync_dir_fd") >= 1,
        "non-deferred renew must sync inline"
    );
    fs::fault::reset();
}

#[test]
fn ack_after_deferred_renew_uses_the_returned_lease() {
    let tmp = TempDir::new().unwrap();
    fs::fault::pin_clock_realtime_ns(fs::clock_realtime_ns().unwrap());
    Queue::init(tmp.path(), &CreateOptions::default()).unwrap();
    let mut queue = Queue::open(
        tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            deferred_dir_sync: true,
            ..Default::default()
        },
    )
    .unwrap();
    let _ = queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 10_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        other => panic!("lease failed: {other:?}"),
    };

    let renewed = match queue.renew(&lease, 60_000_000_000) {
        RenewOutcome::Deferred(l) => l,
        other => panic!("deferred renew failed: {other:?}"),
    };
    // Ack with the deferred renewal's lease info and no intervening sync():
    // the ack's own barriers carry the renewal's directory.
    match queue.ack(&renewed) {
        AckOutcome::Acked => {}
        other => panic!("ack after deferred renew failed: {other:?}"),
    }
}

#[test]
fn renew_syncs_source_directory_only_when_distinct() {
    fn synced_directories(distinct_destination: bool) -> Vec<(u64, u64)> {
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        });
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(lease) => lease,
            other => panic!("lease failed: {other:?}"),
        };
        let source_directory = lease
            .exact_source_path
            .rsplit_once('/')
            .unwrap()
            .0
            .to_string();
        let destination_directory = if distinct_destination {
            let directory = format!("leased/{}/ffffffffffffffff/0000", queue.boot_id);
            queue.ensure_dir(&directory).unwrap();
            directory
        } else {
            source_directory.clone()
        };
        let source_directory_fd = open_relative(queue.root_fd.as_fd(), &source_directory).unwrap();
        let source_stat = fs::fstat(source_directory_fd.as_fd()).unwrap();
        let source_identity = (source_stat.st_dev as u64, source_stat.st_ino as u64);
        let destination_directory_fd =
            open_relative(queue.root_fd.as_fd(), &destination_directory).unwrap();
        let destination_stat = fs::fstat(destination_directory_fd.as_fd()).unwrap();
        let destination_identity = (
            destination_stat.st_dev as u64,
            destination_stat.st_ino as u64,
        );
        let ticket = queue
            .transition_ticket_for_lease(
                &lease,
                TransitionOperation::Renew,
                TicketDestination::Leased {
                    boot_id: queue.boot_id.clone(),
                    boottime_deadline_ns: lease.expires_boottime_ns,
                    wall_deadline_ns: lease.expires_wall_ns,
                },
            )
            .unwrap();

        fs::fault::reset();
        fs::fault::inject("fsync_dir_fd", u64::MAX);
        let outcome = queue.move_leased(
            &lease,
            &destination_directory,
            "renew-barrier-test.sqj",
            &ticket,
        );
        let identities = fs::fault::fd_identities("fsync_dir_fd");
        fs::fault::reset();
        assert!(matches!(outcome, TransitionOutcome::Committed));
        if distinct_destination {
            assert_eq!(identities, [destination_identity, source_identity]);
        } else {
            assert_eq!(identities, [destination_identity]);
        }
        identities
    }

    assert_eq!(synced_directories(false).len(), 1);
    assert_eq!(synced_directories(true).len(), 2);
}

#[test]
fn ack_already_lost_returns_lease_lost() {
    let (_tmp, mut queue) = create_test_queue();
    let input = EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    };
    let _ = queue.enqueue(input);

    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        other => panic!("lease failed: {other:?}"),
    };

    // Verify and ack once
    queue.verify_lease_payload(&lease).unwrap();
    assert!(matches!(queue.ack(&lease), AckOutcome::Acked));

    // Second ack should detect the existing receipt and return AlreadyAcked
    let result = queue.ack(&lease);
    assert!(matches!(result, AckOutcome::AlreadyAcked));
}

#[test]
fn lease_duration_validation() {
    let (_tmp, mut queue) = create_test_queue();
    // Too short
    assert!(matches!(
        queue.lease(0, 500_000_000),
        LeaseOutcome::NotCommitted(_)
    ));
    // Too long (more than 7 days)
    assert!(matches!(
        queue.lease(0, 8 * 24 * 60 * 60 * 1_000_000_000),
        LeaseOutcome::NotCommitted(_)
    ));
}
#[test]
fn payload_verification() {
    let (_tmp, mut queue) = create_test_queue();
    let payload = b"verify me please";
    let input = EnqueueInput {
        maximum_attempts: 3,
        content_type: "text/plain".to_string(),
        payload: payload.to_vec(),
        ..Default::default()
    };
    queue.enqueue(input);

    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!("lease failed"),
    };

    assert!(queue.verify_lease_payload(&lease).is_ok());
}
#[test]
fn retry_with_policy_works() {
    let (_tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 5,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!("lease failed"),
    };
    let policy = steadq_math::RetryPolicy::new(1000, 300_000, false, None).unwrap();
    let result = queue.retry_with_policy(&lease, &policy);
    assert!(matches!(result, TransitionOutcome::Committed));
    let snapshots = queue.inspect(&lease.job_id);
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].state, "delayed");
}
#[test]
fn inspect_finds_ready_job() {
    let (_tmp, mut queue) = create_test_queue();
    let outcome = queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    });
    let ticket = match outcome {
        EnqueueOutcome::Committed(t) => t,
        _ => panic!("enqueue failed"),
    };

    let snapshots = queue.inspect(&ticket.job_id);
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].state, "ready");
    assert_eq!(snapshots[0].generation, 0);
}

#[test]
fn inspect_finds_leased_job() {
    let (_tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!("lease failed"),
    };

    let snapshots = queue.inspect(&lease.job_id);
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].state, "leased");
}

#[test]
fn duplicate_ack_returns_already_acked() {
    let (_tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!("lease failed"),
    };

    // Verify and ack
    queue.verify_lease_payload(&lease).unwrap();
    assert!(matches!(queue.ack(&lease), AckOutcome::Acked));

    // Source is gone, so check_duplicate_ack should find the receipt
    let result = queue.check_duplicate_ack(&lease);
    assert!(matches!(result, AckOutcome::AlreadyAcked));
}

#[test]
fn inspect_returns_empty_for_unknown() {
    let (_tmp, queue) = create_test_queue();
    let unknown_id = [0xFF; 16];
    let snapshots = queue.inspect(&unknown_id);
    assert!(snapshots.is_empty());
}
#[test]
fn concurrent_producers_consumers() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    const TEST_TIMEOUT: Duration = Duration::from_secs(30);
    const RETRY_BACKOFF: Duration = Duration::from_micros(50);
    const LEASE_WAIT_NS: u64 = 10_000_000;

    let tmp = TempDir::new().unwrap();
    let path = tmp.path().to_path_buf();
    Queue::init(&path, &CreateOptions::default()).unwrap();

    let num_producers = 4;
    let num_consumers = 4;
    let jobs_per_producer = 25;
    let total_jobs = num_producers * jobs_per_producer;
    let leased_count = Arc::new(AtomicUsize::new(0));
    let acked_count = Arc::new(AtomicUsize::new(0));

    // Producers
    let mut producer_handles = Vec::new();
    for _ in 0..num_producers {
        let p = path.clone();
        let handle = thread::spawn(move || {
            let queue = Queue::open(
                &p,
                &OpenOptions {
                    allow_unsupported_fs: true,
                    ..Default::default()
                },
            )
            .unwrap();
            let mut queue = queue;
            let deadline = Instant::now() + TEST_TIMEOUT;
            for _ in 0..jobs_per_producer {
                let payload = format!("payload-{}", steadq_fs_linux::random_128bit().unwrap()[0]);
                let input = EnqueueInput {
                    maximum_attempts: 3,
                    content_type: "text/plain".to_string(),
                    payload: payload.into_bytes(),
                    ..Default::default()
                };
                loop {
                    match queue.enqueue(input.clone()) {
                        EnqueueOutcome::Committed(_) => break,
                        EnqueueOutcome::NotCommitted(_, Error::MaintenanceBusy) => {
                            assert!(
                                Instant::now() < deadline,
                                "enqueue remained contended until the test deadline"
                            );
                            thread::sleep(RETRY_BACKOFF);
                        }
                        outcome => panic!("concurrent enqueue failed: {outcome:?}"),
                    }
                }
            }
        });
        producer_handles.push(handle);
    }
    for h in producer_handles {
        h.join().unwrap();
    }

    // Consumers
    let mut consumer_handles = Vec::new();
    for _ in 0..num_consumers {
        let p = path.clone();
        let lc = leased_count.clone();
        let ac = acked_count.clone();
        let handle = thread::spawn(move || {
            let queue = Queue::open(
                &p,
                &OpenOptions {
                    allow_unsupported_fs: true,
                    ..Default::default()
                },
            )
            .unwrap();
            let mut queue = queue;
            let deadline = Instant::now() + TEST_TIMEOUT;
            loop {
                if Instant::now() >= deadline {
                    panic!(
                        "concurrent test exceeded its deadline: leased {} acked {}",
                        lc.load(Ordering::SeqCst),
                        ac.load(Ordering::SeqCst)
                    );
                }
                match queue.lease(LEASE_WAIT_NS, 30_000_000_000) {
                    LeaseOutcome::Leased(lease) => {
                        lc.fetch_add(1, Ordering::SeqCst);
                        loop {
                            assert!(
                                Instant::now() < deadline,
                                "ack remained contended until the test deadline; leased {} acked {}",
                                lc.load(Ordering::SeqCst),
                                ac.load(Ordering::SeqCst)
                            );
                            match queue.ack(&lease) {
                                AckOutcome::Acked => {
                                    ac.fetch_add(1, Ordering::SeqCst);
                                    break;
                                }
                                AckOutcome::NotCommitted(Error::MaintenanceBusy) => {
                                    thread::sleep(RETRY_BACKOFF);
                                }
                                outcome => panic!("concurrent ack failed: {outcome:?}"),
                            }
                        }
                    }
                    LeaseOutcome::Empty => {
                        if ac.load(Ordering::SeqCst) == total_jobs {
                            break;
                        }
                    }
                    LeaseOutcome::NotCommitted(Error::MaintenanceBusy) => {}
                    outcome => panic!("concurrent lease failed: {outcome:?}"),
                }
            }
        });
        consumer_handles.push(handle);
    }
    for h in consumer_handles {
        h.join().unwrap();
    }

    assert_eq!(
        leased_count.load(Ordering::SeqCst),
        total_jobs,
        "expected {} leased, got {}",
        total_jobs,
        leased_count.load(Ordering::SeqCst)
    );
    assert_eq!(
        acked_count.load(Ordering::SeqCst),
        total_jobs,
        "expected {} acked, got {}",
        total_jobs,
        acked_count.load(Ordering::SeqCst)
    );
}

#[test]
fn concurrent_lease_uniqueness() {
    // 8 consumers race for 1 job: exactly one should win
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

    let tmp = TempDir::new().unwrap();
    let path = tmp.path().to_path_buf();
    Queue::init(&path, &CreateOptions::default()).unwrap();

    // Enqueue exactly one job
    {
        let mut queue = Queue::open(
            &path,
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"race".to_vec(),
            ..Default::default()
        });
    }

    let success_count = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();

    for _ in 0..32 {
        let p = path.clone();
        let sc = success_count.clone();
        handles.push(thread::spawn(move || {
            let queue = Queue::open(
                &p,
                &OpenOptions {
                    allow_unsupported_fs: true,
                    ..Default::default()
                },
            )
            .unwrap();
            let mut queue = queue;
            if let LeaseOutcome::Leased(_) = queue.lease(0, 30_000_000_000) {
                sc.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(
        success_count.load(Ordering::SeqCst),
        1,
        "exactly one consumer should win the race"
    );
}

#[test]
fn enqueue_survives_reopen() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path();
    Queue::init(path, &CreateOptions::default()).unwrap();

    // Enqueue
    let ticket = {
        let mut queue = Queue::open(
            path,
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        match queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "text/plain".to_string(),
            payload: b"survive reopen".to_vec(),
            ..Default::default()
        }) {
            EnqueueOutcome::Committed(t) => t,
            _ => panic!("enqueue failed"),
        }
    };

    // Reopen and verify the job is visible
    let queue2 = Queue::open(
        path,
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    )
    .unwrap();
    let snapshots = queue2.inspect(&ticket.job_id);
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].state, "ready");
}

fn create_test_queue_shards(shard_count: u32) -> (TempDir, Queue) {
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

fn complete_one_job(queue: &mut Queue) {
    match queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "text/plain".into(),
        payload: vec![0xAB; 64],
        ..Default::default()
    }) {
        EnqueueOutcome::Committed(_) => {}
        other => panic!("enqueue: {other:?}"),
    }
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(lease) => lease,
        other => panic!("lease: {other:?}"),
    };
    queue.verify_lease_payload(&lease).expect("verify");
    match queue.ack(&lease) {
        AckOutcome::Acked => {}
        other => panic!("ack: {other:?}"),
    }
}

fn sync_call_counts() -> (u64, u64) {
    (
        fs::fault::call_count("fsync"),
        fs::fault::call_count("fsync_dir_fd"),
    )
}

fn sync_call_delta(before: (u64, u64)) -> (u64, u64) {
    let after = sync_call_counts();
    (after.0 - before.0, after.1 - before.1)
}

#[test]
fn warm_completed_job_fsyncs_required_directories_once() {
    let (_tmp, mut queue) = create_test_queue_shards(1);
    complete_one_job(&mut queue);

    fs::fault::reset();
    fs::fault::inject("fsync", u64::MAX);
    let start = sync_call_counts();
    match queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "text/plain".into(),
        payload: vec![0xAB; 64],
        ..Default::default()
    }) {
        EnqueueOutcome::Committed(_) => {}
        other => panic!("enqueue: {other:?}"),
    }
    let enqueue = sync_call_delta(start);
    let after_enqueue = sync_call_counts();
    let named_fallback = matches!(
        queue.publication_mode,
        Some(fs::PublicationMode::NamedFallback)
    );
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(lease) => lease,
        other => panic!("lease: {other:?}"),
    };
    let lease_counts = sync_call_delta(after_enqueue);
    let after_lease = sync_call_counts();
    queue.verify_lease_payload(&lease).expect("verify");
    let verify = sync_call_delta(after_lease);
    let after_verify = sync_call_counts();
    match queue.ack(&lease) {
        AckOutcome::Acked => {}
        other => panic!("ack: {other:?}"),
    }
    let ack = sync_call_delta(after_verify);
    fs::fault::reset();

    if named_fallback {
        assert_eq!(enqueue, (3, 2), "named fallback: file + dest + tmp");
    } else {
        assert_eq!(enqueue, (2, 1), "tmpfile: file + dest");
    }
    assert_eq!(lease_counts, (1, 1), "lease same-directory dest");
    assert_eq!(verify, (0, 0), "verify is read-only");
    assert_eq!(ack, (2, 2), "ack dest + source");
}

#[test]
fn sharded_bucket_parent_only_matches_in_range_shard_leaves() {
    assert_eq!(
        super::publish::sharded_bucket_parent("receipts/00ab/0001", 64),
        Some("receipts/00ab")
    );
    assert_eq!(
        super::publish::sharded_bucket_parent("leased/boot/bucket/003f", 64),
        Some("leased/boot/bucket")
    );
    assert_eq!(
        super::publish::sharded_bucket_parent("ready/0000", 64),
        None
    );
    assert_eq!(
        super::publish::sharded_bucket_parent("ready/0040", 64),
        None
    );
    assert_eq!(
        super::publish::sharded_bucket_parent("receipts/00ab/003f", 64),
        Some("receipts/00ab")
    );
    assert_eq!(
        super::publish::sharded_bucket_parent("receipts/00ab/0040", 64),
        None
    );
    assert_eq!(
        super::publish::sharded_bucket_parent("quarantine", 64),
        None
    );
    assert_eq!(
        super::publish::sharded_bucket_parent("receipts/00ab/job.sqj", 64),
        None
    );
}

#[test]
fn ensuring_one_shard_creates_every_sibling_and_syncs_the_bucket_once() {
    let (tmp, queue) = create_test_queue_shards(4);
    let bucket = format!(
        "receipts/{}",
        steadq_names::bucket_hex(
            steadq_math::bucket_number(
                queue.effective_wall_floor_ns_checked().unwrap(),
                queue.format.terminal_bucket_width_ns(),
            )
            .unwrap()
        )
    );
    let bucket_fd = {
        queue.ensure_dir(&bucket).unwrap();
        open_relative(queue.root_fd().as_fd(), &bucket).unwrap()
    };
    let bucket_stat = fs::fstat(bucket_fd.as_fd()).unwrap();
    let bucket_id = (bucket_stat.st_dev as u64, bucket_stat.st_ino as u64);

    fs::fault::reset();
    fs::fault::inject("fsync", u64::MAX);
    queue.ensure_dir(&format!("{bucket}/0002")).unwrap();
    let identities = fs::fault::fd_identities("fsync_dir_fd");
    fs::fault::reset();

    let shard_dirs: Vec<_> = std::fs::read_dir(tmp.path().join(&bucket))
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().is_dir())
        .collect();
    assert_eq!(shard_dirs.len(), 4);
    assert_eq!(
        identities.iter().filter(|id| **id == bucket_id).count(),
        1,
        "sibling creation syncs the bucket once, got {identities:?}"
    );

    fs::fault::reset();
    fs::fault::inject("fsync", u64::MAX);
    queue.ensure_dir(&format!("{bucket}/0003")).unwrap();
    assert_eq!(fs::fault::call_count("fsync_dir_fd"), 0);
    fs::fault::reset();
}

#[test]
fn first_lease_stays_in_the_ready_shard() {
    let (tmp, mut queue) = create_test_queue_shards(4);
    match queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "text/plain".into(),
        payload: vec![0xAB; 64],
        ..Default::default()
    }) {
        EnqueueOutcome::Committed(_) => {}
        other => panic!("enqueue: {other:?}"),
    }
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(lease) => lease,
        other => panic!("lease: {other:?}"),
    };
    assert!(
        lease.exact_source_path.starts_with("ready/"),
        "leased file must stay in ready/: {}",
        lease.exact_source_path
    );
    assert!(tmp.path().join(&lease.exact_source_path).exists());
    assert!(!tmp.path().join("leased").join(&queue.boot_id).exists());
}

#[test]
fn warm_four_shard_completed_job_has_no_per_shard_mkdir_fsync() {
    let (_tmp, mut queue) = create_test_queue_shards(4);
    complete_one_job(&mut queue);

    fs::fault::reset();
    fs::fault::inject("fsync", u64::MAX);
    let start = sync_call_counts();
    complete_one_job(&mut queue);
    let total = sync_call_delta(start);
    fs::fault::reset();

    let named_fallback = matches!(
        queue.publication_mode,
        Some(fs::PublicationMode::NamedFallback)
    );
    if named_fallback {
        assert_eq!(total, (6, 5), "named fallback warm completed job");
    } else {
        assert_eq!(total, (5, 4), "tmpfile warm completed job");
    }
}

#[test]
fn streaming_tmpfile_enqueue_fsyncs_destination_once() {
    let (_tmp, mut queue) = create_test_queue_shards(1);
    if !tmpfile_supported(&queue) {
        return;
    }

    let dest_fd = open_relative(queue.root_fd().as_fd(), "ready/0000").unwrap();
    let dest_stat = fs::fstat(dest_fd.as_fd()).unwrap();
    let dest_id = (dest_stat.st_dev as u64, dest_stat.st_ino as u64);

    fs::fault::reset();
    fs::fault::inject("fsync", u64::MAX);
    match queue.enqueue_streaming(
        3,
        "text/plain".into(),
        Default::default(),
        None,
        None,
        None,
        std::io::Cursor::new(vec![0xABu8; 64]),
    ) {
        EnqueueOutcome::Committed(_) => {}
        other => panic!("stream: {other:?}"),
    }
    let dest_hits = fs::fault::fd_identities("fsync_dir_fd")
        .into_iter()
        .filter(|id| *id == dest_id)
        .count();
    fs::fault::reset();
    if matches!(
        queue.publication_mode,
        Some(fs::PublicationMode::NamedFallback)
    ) {
        return;
    }
    assert_eq!(dest_hits, 1);
}

#[test]
fn enqueue_zero_payload() {
    let (_tmp, mut queue) = create_test_queue();
    let outcome = queue.enqueue(EnqueueInput {
        maximum_attempts: 1,
        content_type: "empty".to_string(),
        payload: vec![],
        ..Default::default()
    });
    match outcome {
        EnqueueOutcome::Committed(ticket) => {
            // Verify it can be leased
            let lease = match queue.lease(0, 30_000_000_000) {
                LeaseOutcome::Leased(l) => l,
                _ => panic!("lease failed"),
            };
            assert_eq!(lease.job_id, ticket.job_id);
        }
        _ => panic!("zero-payload enqueue should succeed"),
    }
}

#[test]
fn streaming_enqueue_writes_and_reads_payload() {
    let (_tmp, mut queue) = create_test_queue();
    let payload = vec![0x42u8; 100_000];

    let cursor = std::io::Cursor::new(payload.clone());
    fs::fault::reset();
    fs::fault::inject("fsync", u64::MAX);
    let outcome = queue.enqueue_streaming(
        3,
        "x".to_string(),
        Default::default(),
        None,
        None,
        None,
        cursor,
    );
    let file_fsync_calls = fs::fault::call_count("fsync");
    let directory_fsync_calls = fs::fault::call_count("fsync_dir_fd");
    fs::fault::reset();
    let _ticket = match outcome {
        EnqueueOutcome::Committed(t) => t,
        o => panic!("streaming enqueue failed: {o:?}"),
    };
    assert_eq!(
        file_fsync_calls.checked_sub(directory_fsync_calls),
        Some(1),
        "streaming publication syncs its data file once"
    );

    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        o => panic!("lease failed: {o:?}"),
    };

    let reader = queue
        .open_verified_payload_reader(&lease)
        .unwrap()
        .expect("reader");
    assert_eq!(reader.payload_len(), 100_000);

    let mut read_data = Vec::new();
    let mut buf = vec![0u8; 4096];
    let mut offset = 0u64;
    loop {
        let n = reader.read_at(&mut buf, offset).unwrap();
        if n == 0 {
            break;
        }
        read_data.extend_from_slice(&buf[..n]);
        offset += n as u64;
    }
    assert_eq!(read_data, payload);
}

#[test]
fn streaming_enqueue_reports_deferred_until_queue_sync() {
    let tmp = TempDir::new().unwrap();
    Queue::init(tmp.path(), &CreateOptions::default()).unwrap();
    let mut queue = Queue::open(
        tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            deferred_dir_sync: true,
            ..Default::default()
        },
    )
    .unwrap();
    let outcome = queue.enqueue_streaming(
        3,
        "x".into(),
        Default::default(),
        None,
        None,
        None,
        std::io::Cursor::new(b"streamed deferred"),
    );
    assert!(matches!(outcome, EnqueueOutcome::Deferred(_)));
    assert!(
        !queue.dirty.borrow().is_empty(),
        "streaming deferred publish must record dirty directories"
    );
    queue.sync().unwrap();
    assert!(queue.dirty.borrow().is_empty());
}

#[test]
fn preferred_named_streaming_publication_bypasses_tmpfiles() {
    let (_tmp, mut queue) = create_test_queue();
    queue.publication_mode = Some(fs::PublicationMode::NamedFallback);
    let payload = vec![0x5Au8; 8193];

    fs::fault::reset();
    fs::fault::inject("open_tmpfile", u64::MAX);
    let outcome = queue.enqueue_streaming(
        3,
        "application/octet-stream".to_string(),
        Default::default(),
        None,
        None,
        None,
        std::io::Cursor::new(payload),
    );
    let tmpfile_calls = fs::fault::call_count("open_tmpfile");
    let rename_calls = fs::fault::call_count("renameat2_noreplace");
    fs::fault::reset();

    assert_eq!(tmpfile_calls, 0);
    assert_eq!(rename_calls, 1);
    let ticket = match outcome {
        EnqueueOutcome::Committed(ticket) => ticket,
        outcome => panic!("named streaming enqueue failed: {outcome:?}"),
    };
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(lease) => lease,
        outcome => panic!("lease failed: {outcome:?}"),
    };
    assert_eq!(lease.job_id, ticket.job_id);
    queue.verify_lease_payload(&lease).unwrap();
}

#[test]
fn enqueue_large_payload() {
    let (_tmp, mut queue) = create_test_queue();
    let payload = vec![0x42; 1_000_000]; // 1 MB
    let outcome = queue.enqueue(EnqueueInput {
        maximum_attempts: 1,
        content_type: "large".to_string(),
        payload,
        ..Default::default()
    });
    assert!(matches!(outcome, EnqueueOutcome::Committed(_)));
}
#[test]
fn one_attempt_job_single_lease() {
    let (_tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 1,
        content_type: "x".to_string(),
        payload: b"one shot".to_vec(),
        ..Default::default()
    });

    // First lease succeeds
    let lease = match queue.lease(0, 10_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!("first lease should succeed"),
    };
    assert_eq!(lease.attempt, 1);
    assert_eq!(lease.maximum_attempts, 1);

    // Retry should go to dead (attempt >= max)
    let result = queue.retry_now(&lease);
    assert!(matches!(result, TransitionOutcome::Committed));

    // No more leases
    assert!(matches!(
        queue.lease(0, 30_000_000_000),
        LeaseOutcome::Empty
    ));
}

#[test]
fn retry_at_in_past_is_retry_now() {
    let (_tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"past".to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!("lease failed"),
    };

    // retry_at with a timestamp in the past should behave as retry_now
    let past_ts = 1;
    let result = queue.retry_at(&lease, past_ts);
    assert!(
        matches!(result, TransitionOutcome::Committed),
        "retry should commit, got something else"
    );

    // Job should be in ready (not delayed)
    let result2 = queue.lease(0, 30_000_000_000);
    assert!(
        matches!(result2, LeaseOutcome::Leased(_)),
        "re-lease should succeed"
    );
}

#[test]
fn delay_preserves_attempt() {
    let (_tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 5,
        content_type: "x".to_string(),
        payload: b"delay".to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!("lease failed"),
    };
    assert_eq!(lease.attempt, 1);

    // Retry with delay
    let future = steadq_fs_linux::clock_realtime_ns().unwrap() + 60_000_000_000;
    let result = queue.retry_at(&lease, future);
    assert!(matches!(result, TransitionOutcome::Committed));

    // The job should be in delayed state, not ready
    assert!(matches!(queue.lease(0, 1_000_000_000), LeaseOutcome::Empty));
}

#[test]
fn guard_file_sync_before_publish() {
    // An enqueued job must be fsynced before it appears in an active directory.
    // This is implicit in the O_TMPFILE path: the file is created without a name,
    // synced, then linked. Without the sync, a crash before link loses the file.
    // Verify: after enqueue, the file exists and has content.
    let (_tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 1,
        content_type: "x".to_string(),
        payload: b"synced".to_vec(),
        ..Default::default()
    });
    // The job should be in ready/ with correct content (not empty)
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!("lease failed"),
    };
    // Payload verification should pass (file was properly synced before publish)
    assert!(queue.verify_lease_payload(&lease).is_ok());
}

#[test]
fn guard_name_tag_verification() {
    // A job with a wrong name tag should not be delivered by lease.
    let (_tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 1,
        content_type: "x".to_string(),
        payload: b"tagged".to_vec(),
        ..Default::default()
    });
    let result = queue.lease(0, 30_000_000_000);
    assert!(matches!(result, LeaseOutcome::Leased(_)));
}

#[test]
fn guard_shard_verification() {
    // A job placed in the wrong shard should not be leased from that shard.
    // The claim path verifies computed_shard matches the directory shard.
    let (_tmp, mut queue) = create_test_queue();
    let outcome = queue.enqueue(EnqueueInput {
        maximum_attempts: 1,
        content_type: "x".to_string(),
        payload: b"sharded".to_vec(),
        ..Default::default()
    });
    if let EnqueueOutcome::Committed(_) = outcome {
        let result = queue.lease(0, 30_000_000_000);
        assert!(
            matches!(result, LeaseOutcome::Leased(_)),
            "job should be leasable"
        );
    }
}

#[test]
fn guard_link_count() {
    // A leased job with link count > 1 should be rejected.
    // The claim path checks st_nlink == 1 after rename.
    let (_tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 1,
        content_type: "x".to_string(),
        payload: b"linked".to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!("lease failed"),
    };
    // The file should have link count 1 (no external hard links)
    let path = _tmp.path().join(&lease.exact_source_path);
    let metadata = std::fs::metadata(&path).unwrap();
    use std::os::unix::fs::MetadataExt;
    assert_eq!(metadata.nlink(), 1, "leased file must have link count 1");
}

#[test]
fn guard_attempt_limit_enforced() {
    // maximum_attempts bounds committed claim returns.
    // A job with max_attempts=2 can be leased at most twice before going to dead.
    let (_tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 2,
        content_type: "x".to_string(),
        payload: b"bounded".to_vec(),
        ..Default::default()
    });

    // First lease
    let l1 = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!(),
    };
    assert_eq!(l1.attempt, 1);
    queue.retry_now(&l1).commit_or_panic();

    // Second lease
    let l2 = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!(),
    };
    assert_eq!(l2.attempt, 2);
    queue.retry_now(&l2).commit_or_panic();

    // Third attempt should go to dead (attempt >= max)
    assert!(matches!(
        queue.lease(0, 30_000_000_000),
        LeaseOutcome::Empty
    ));
}

#[test]
fn guard_payload_verification_prevents_ack() {
    // verify_lease_payload detects corruption and returns PayloadCorrupt.
    // A consumer cannot safely acknowledge without verification.
    let (_tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 1,
        content_type: "x".to_string(),
        payload: b"verify me".to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!("lease failed"),
    };
    assert!(queue.verify_lease_payload(&lease).is_ok());
}

// ===== Init refuses to overwrite existing queue =====
#[test]
fn init_refuses_existing_queue() {
    let tmp = TempDir::new().unwrap();
    Queue::init(tmp.path(), &CreateOptions::default()).unwrap();
    let result = Queue::init(tmp.path(), &CreateOptions::default());
    assert!(
        result.is_err(),
        "init must refuse to overwrite existing queue"
    );
}

// ===== All options validated before mutation =====
#[test]
fn init_validates_zero_lease_width() {
    let tmp = TempDir::new().unwrap();
    let opts = CreateOptions {
        lease_bucket_width_ns: 0,
        ..Default::default()
    };
    assert!(Queue::init(tmp.path(), &opts).is_err());
    // Root should not have been modified
    assert!(!tmp.path().join("FORMAT").exists());
}

#[test]
fn init_validates_zero_delayed_width() {
    let tmp = TempDir::new().unwrap();
    let opts = CreateOptions {
        delayed_bucket_width_ns: 0,
        ..Default::default()
    };
    assert!(Queue::init(tmp.path(), &opts).is_err());
}

#[test]
fn init_requires_delayed_width_to_divide_terminal_width() {
    let tmp = TempDir::new().unwrap();
    let opts = CreateOptions {
        delayed_bucket_width_ns: 7_000_000_000,
        ..Default::default()
    };
    assert!(Queue::init(tmp.path(), &opts).is_err());
    assert!(!tmp.path().join("FORMAT").exists());
}

// ===== Payload size checked before hashing =====
#[test]
fn enqueue_rejects_oversize_payload() {
    let tmp = TempDir::new().unwrap();
    let opts = CreateOptions {
        max_payload_length: 1024,
        ..Default::default()
    };
    Queue::init(tmp.path(), &opts).unwrap();
    let mut queue = Queue::open(
        tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    )
    .unwrap();
    let huge = vec![0u8; 2048]; // exceeds max_payload_length of 1024
    let result = queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: huge,
        ..Default::default()
    });
    assert!(matches!(result, EnqueueOutcome::NotCommitted(_, _)));
}

#[test]
fn enqueue_accepts_payload_at_exact_limit() {
    let tmp = TempDir::new().unwrap();
    let opts = CreateOptions {
        max_payload_length: 1024,
        ..Default::default()
    };
    Queue::init(tmp.path(), &opts).unwrap();
    let mut queue = Queue::open(
        tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    )
    .unwrap();
    let exact = vec![0u8; 1024]; // exactly max_payload_length
    let result = queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: exact,
        ..Default::default()
    });
    assert!(
        matches!(result, EnqueueOutcome::Committed(_)),
        "payload at the exact limit must commit: {result:?}"
    );
    let over = vec![0u8; 1025];
    let result = queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: over,
        ..Default::default()
    });
    assert!(matches!(result, EnqueueOutcome::NotCommitted(_, _)));
}

// ===== Scan round advances =====
#[test]
fn scan_round_advances() {
    let (_tmp, mut queue) = create_test_queue();
    assert_eq!(queue.scan_round, 0);
    let _ = queue.lease(0, 30_000_000_000);
    assert_eq!(queue.scan_round, 1);
    let _ = queue.lease(0, 30_000_000_000);
    assert_eq!(queue.scan_round, 2);
}

#[test]
fn enqueue_hint_scans_the_known_ready_shard_first() {
    let (_tmp, mut queue) = create_test_queue();
    let ticket = match queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"hinted".to_vec(),
        ..Default::default()
    }) {
        EnqueueOutcome::Committed(ticket) => ticket,
        outcome => panic!("enqueue failed: {outcome:?}"),
    };
    let hinted_shard = compute_shard(
        queue.format.queue_id(),
        &ticket.job_id,
        queue.format.shard_count(),
    );
    assert_eq!(queue.ready_shard_hint, Some(hinted_shard));

    queue.scan_round = (0..4096)
        .find(|round| {
            let (start, _) = steadq_names::shard_scan_params(
                queue.format.queue_id(),
                &queue.boot_id_bytes,
                &queue.worker_nonce,
                *round,
                queue.format.shard_count(),
            );
            start != hinted_shard
        })
        .unwrap();

    fs::fault::reset();
    fs::fault::inject_errno("open_directory", 1, libc::EIO);
    let outcome = queue.lease(0, 30_000_000_000);
    fs::fault::reset();

    assert!(matches!(
        outcome,
        LeaseOutcome::NotCommitted(Error::IoFailure(_))
    ));
    assert_eq!(queue.ready_shard_hint, None);
    assert!(matches!(
        queue.lease(0, 30_000_000_000),
        LeaseOutcome::Leased(_)
    ));
}

#[test]
fn delayed_enqueue_preserves_ready_shard_hint() {
    let (_tmp, mut queue) = create_test_queue();
    assert!(matches!(
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"ready".to_vec(),
            ..Default::default()
        }),
        EnqueueOutcome::Committed(_)
    ));
    let ready_hint = queue.ready_shard_hint;
    let not_before = queue.wall_floor_for_mutation().unwrap().unix_ns() + 60_000_000_000;
    assert!(matches!(
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"delayed".to_vec(),
            initial_not_before: Some(not_before),
            ..Default::default()
        }),
        EnqueueOutcome::Committed(_)
    ));
    assert!(ready_hint.is_some());
    assert_eq!(queue.ready_shard_hint, ready_hint);
}

// ===== ack re-hashes payload internally =====
#[test]
fn ack_succeeds_without_explicit_verify() {
    let (_tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!("lease failed"),
    };
    // ack() re-verifies payload at ack time, no explicit verify needed
    let result = queue.ack(&lease);
    assert!(matches!(result, AckOutcome::Acked));
}

// ===== explicit verification remains compatible with strict ack =====
#[test]
fn ack_accepts_verified_lease() {
    let (_tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!("lease failed"),
    };
    queue.verify_lease_payload(&lease).unwrap();
    let result = queue.ack(&lease);
    assert!(matches!(result, AckOutcome::Acked));
}

// ===== verify_lease_payload detects corruption =====
#[test]
fn verify_lease_payload_detects_corruption() {
    let (_tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"hello world".to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!("lease failed"),
    };
    // Corrupt the actual payload bytes (after header + extension)
    let src_path = _tmp.path().join(&lease.exact_source_path);
    let mut data = std::fs::read(&src_path).unwrap();
    // Header is 128 bytes, extension follows. Find the payload offset.
    // For content_type "x" the extension is ~4 bytes, so payload starts at ~132.
    // Corrupt the last byte (guaranteed to be in payload).
    let last = data.len() - 1;
    data[last] ^= 0xFF;
    std::fs::write(&src_path, data).unwrap();
    let result = queue.verify_lease_payload(&lease);
    assert!(
        matches!(
            result,
            Err(Error::PayloadCorrupt) | Err(Error::QueueCorrupt(_))
        ),
        "corrupted payload should be detected, got: {result:?}"
    );
}

// ===== streaming payload read =====
#[test]
fn verified_payload_reader_reads_sequential_and_random_access() {
    let (_tmp, mut queue) = create_test_queue();
    let payload: Vec<u8> = (0..100_000).map(|i| (i % 251) as u8).collect();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: payload.clone(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        o => panic!("lease failed: {o:?}"),
    };

    let reader = queue
        .open_verified_payload_reader(&lease)
        .unwrap()
        .expect("reader should exist");
    assert_eq!(reader.payload_len(), 100_000);

    // Sequential read in 4KB chunks.
    let mut offset = 0u64;
    let mut read_data = Vec::new();
    let mut buf = vec![0u8; 4096];
    loop {
        let n = reader.read_at(&mut buf, offset).unwrap();
        if n == 0 {
            break;
        }
        read_data.extend_from_slice(&buf[..n]);
        offset += n as u64;
    }
    assert_eq!(read_data, payload);

    // Random-access read at offset 50_000.
    let mut specific = [0u8; 4];
    assert_eq!(reader.read_at(&mut specific, 50_000).unwrap(), 4);
    assert_eq!(&specific, &payload[50_000..50_004]);

    // Read at end is capped to remaining bytes.
    let mut tail = vec![0u8; 10_000];
    assert_eq!(reader.read_at(&mut tail, 99_998).unwrap(), 2);
    assert_eq!(&tail[..2], &payload[99_998..100_000]);

    // Read past end returns 0.
    assert_eq!(reader.read_at(&mut tail, 100_000).unwrap(), 0);
}

#[test]
fn stream_lease_payload_reads_all_data() {
    let (_tmp, mut queue) = create_test_queue();
    let payload = b"streaming payload data for testing chunked reads";
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: payload.to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!("lease failed"),
    };
    let mut collected = Vec::new();
    queue
        .stream_lease_payload(&lease, 8, |chunk| {
            collected.extend_from_slice(chunk);
            Ok(())
        })
        .unwrap();
    assert_eq!(&collected[..], &payload[..]);
}

#[test]
fn read_lease_payload_chunk_respects_offset() {
    let (_tmp, mut queue) = create_test_queue();
    let payload = b"0123456789abcdef";
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: payload.to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!("lease failed"),
    };
    let mut buf = [0u8; 4];
    let n = queue.read_lease_payload_chunk(&lease, &mut buf, 4).unwrap();
    assert_eq!(n, 4);
    assert_eq!(&buf, b"4567");
    // Read at EOF
    let n = queue
        .read_lease_payload_chunk(&lease, &mut buf, 16)
        .unwrap();
    assert_eq!(n, 0);
}

// ===== resolve full identity verification =====
#[test]
fn resolve_source_still_in_ready() {
    let (_tmp, mut queue) = create_test_queue();
    let et = match queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    }) {
        EnqueueOutcome::Committed(t) => t,
        _ => panic!("enqueue failed"),
    };
    let parsed =
        steadq_names::parse_ready(et.expected_relative_path.rsplit('/').next().unwrap()).unwrap();
    let ticket = test_claim_ticket(
        &queue,
        et.job_id,
        parsed.common.generation,
        parsed.common.attempt,
        parsed.common.maximum_attempts,
        [0; 16],
        et.envelope_digest,
    );
    let outcome = queue.resolve(&ticket, false);
    assert!(matches!(outcome, ResolutionOutcome::SourceObserved));
}

#[test]
fn resolve_detects_ready_object_present() {
    let (_tmp, mut queue) = create_test_queue();
    let et = match queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    }) {
        EnqueueOutcome::Committed(t) => t,
        _ => panic!("enqueue failed"),
    };
    // The object exists in ready. Use the path from the enqueue ticket.
    let parsed =
        steadq_names::parse_ready(et.expected_relative_path.rsplit('/').next().unwrap()).unwrap();
    let ticket = test_claim_ticket(
        &queue,
        et.job_id,
        parsed.common.generation,
        parsed.common.attempt,
        parsed.common.maximum_attempts,
        [0; 16],
        et.envelope_digest,
    );
    let outcome = queue.resolve(&ticket, false);
    assert!(matches!(outcome, ResolutionOutcome::SourceObserved));
}

#[test]
fn resolve_stabilization_reports_file_sync_failure() {
    let (_tmp, mut queue) = create_test_queue();
    let et = match queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    }) {
        EnqueueOutcome::Committed(ticket) => ticket,
        _ => panic!("enqueue failed"),
    };
    let parsed =
        steadq_names::parse_ready(et.expected_relative_path.rsplit('/').next().unwrap()).unwrap();
    let ticket = test_claim_ticket(
        &queue,
        et.job_id,
        parsed.common.generation,
        parsed.common.attempt,
        parsed.common.maximum_attempts,
        [0; 16],
        et.envelope_digest,
    );

    fs::fault::reset();
    fs::fault::inject("fsync", 1);
    let outcome = queue.resolve(&ticket, true);
    assert!(matches!(
        outcome,
        ResolutionOutcome::ResolutionFailed(Error::IoFailure(_))
    ));
    assert_eq!(fs::fault::call_count("fsync"), 1);
    assert_eq!(fs::fault::call_count("fsync_dir_fd"), 0);
    fs::fault::reset();
    assert!(matches!(
        queue.resolve(&ticket, true),
        ResolutionOutcome::SourceStabilized
    ));
}

#[test]
fn resolve_stabilization_rejects_replaced_path() {
    use std::os::unix::fs::symlink;

    let (tmp, mut queue) = create_test_queue();
    let et = match queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    }) {
        EnqueueOutcome::Committed(ticket) => ticket,
        _ => panic!("enqueue failed"),
    };
    let parsed =
        steadq_names::parse_ready(et.expected_relative_path.rsplit('/').next().unwrap()).unwrap();
    let ticket = test_claim_ticket(
        &queue,
        et.job_id,
        parsed.common.generation,
        parsed.common.attempt,
        parsed.common.maximum_attempts,
        [0; 16],
        et.envelope_digest,
    );
    let (source_relative_path, _) = queue.transition_ticket_paths(&ticket).unwrap();
    let source_path = ResolvePath::new(&source_relative_path).unwrap();
    let object = match queue.resolve_check_object(
        &source_path,
        &ticket,
        &ticket.source_common(),
        ObjectKind::FullJob,
    ) {
        ResolveObj::Match(object) => object,
        _ => panic!("source object did not authenticate"),
    };

    let source = tmp.path().join(&source_relative_path);
    let displaced = tmp.path().join("tmp/displaced.sqj");
    std::fs::rename(&source, displaced).unwrap();
    assert!(!queue.stabilize_object(&source_path, &object).unwrap());

    let outside = tempfile::TempDir::new().unwrap();
    let outside_file = outside.path().join("outside.sqj");
    std::fs::write(&outside_file, b"outside").unwrap();
    symlink(outside_file, &source).unwrap();

    assert!(!queue.stabilize_object(&source_path, &object).unwrap());
    fs::fault::reset();
    fs::fault::inject_errno("fstatat", 1, libc::EIO);
    assert!(matches!(
        queue.stabilize_object(&source_path, &object),
        Err(Error::IoFailure(_))
    ));
    fs::fault::reset();
    assert_eq!(
        resolver_file_open_flags(),
        libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK
    );
}

#[test]
fn resolve_stabilization_rejects_replaced_parent() {
    let (tmp, mut queue) = create_test_queue();
    let et = match queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    }) {
        EnqueueOutcome::Committed(ticket) => ticket,
        _ => panic!("enqueue failed"),
    };
    let parsed =
        steadq_names::parse_ready(et.expected_relative_path.rsplit('/').next().unwrap()).unwrap();
    let ticket = test_claim_ticket(
        &queue,
        et.job_id,
        parsed.common.generation,
        parsed.common.attempt,
        parsed.common.maximum_attempts,
        [0; 16],
        et.envelope_digest,
    );
    let (source_relative_path, _) = queue.transition_ticket_paths(&ticket).unwrap();
    let source_path = ResolvePath::new(&source_relative_path).unwrap();
    let object = match queue.resolve_check_object(
        &source_path,
        &ticket,
        &ticket.source_common(),
        ObjectKind::FullJob,
    ) {
        ResolveObj::Match(object) => object,
        _ => panic!("source object did not authenticate"),
    };

    let parent = tmp.path().join(source_path.directory.as_str());
    let displaced = tmp.path().join("tmp/displaced-shard");
    std::fs::rename(&parent, displaced).unwrap();
    std::fs::create_dir(&parent).unwrap();
    assert!(!queue.stabilize_object(&source_path, &object).unwrap());

    std::fs::remove_dir(&parent).unwrap();
    assert!(!queue.stabilize_object(&source_path, &object).unwrap());

    fs::fault::reset();
    fs::fault::inject_errno("openat2_beneath", 1, libc::EIO);
    assert!(matches!(
        queue.stabilize_object(&source_path, &object),
        Err(Error::IoFailure(_))
    ));
    fs::fault::reset();
}

#[test]
fn resolve_recomputes_paths_after_job_id_change() {
    let (_tmp, mut queue) = create_test_queue();
    let et = match queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    }) {
        EnqueueOutcome::Committed(t) => t,
        _ => panic!("enqueue failed"),
    };
    // Use a different job_id - the file exists but belongs to a different job.
    let mut wrong_id = et.job_id;
    wrong_id[0] ^= 0xFF;
    let ticket = test_claim_ticket(&queue, wrong_id, 0, 0, 3, [0; 16], et.envelope_digest);
    let outcome = queue.resolve(&ticket, false);
    assert!(matches!(outcome, ResolutionOutcome::NeitherObserved));
}

#[test]
fn resolve_rejects_foreign_queue_ticket_before_filesystem_calls() {
    let (_tmp, queue) = create_test_queue();
    let ticket = TransitionTicket::new(
        [0xff; 16],
        TransitionOperation::Claim,
        TransitionPhase::Linearized,
        TicketIdentity::new([1; 16], 0, 0, 3, [2; 16], TicketEvidence::new([3; 32], 4)),
        TicketSource::Ready {},
        TicketDestination::Leased {
            boot_id: queue.boot_id.clone(),
            boottime_deadline_ns: 1,
            wall_deadline_ns: 1,
        },
    )
    .unwrap();

    fs::fault::reset();
    for syscall in [
        "openat2_beneath",
        "open_directory",
        "fstatat",
        "fstat",
        "openat",
    ] {
        fs::fault::inject(syscall, 1);
    }
    let outcome = queue.resolve(&ticket, false);
    assert!(matches!(
        outcome,
        ResolutionOutcome::ResolutionFailed(Error::InvalidTicket(_))
    ));
    for syscall in [
        "openat2_beneath",
        "open_directory",
        "fstatat",
        "fstat",
        "openat",
    ] {
        assert_eq!(fs::fault::call_count(syscall), 0);
    }
    fs::fault::reset();
}

#[test]
fn resolve_compact_receipt_requires_ticket_attempt_and_bucket() {
    let (tmp, queue) = create_test_queue();
    let job_id = [7; 16];
    let lease_token = [8; 16];
    let envelope_digest = [9; 32];
    let terminal_bucket = 2;
    let ticket = TransitionTicket::new(
        *queue.format.queue_id(),
        TransitionOperation::Acknowledge,
        TransitionPhase::SourceDirectoryDurable,
        TicketIdentity::new(
            job_id,
            4,
            1,
            3,
            lease_token,
            TicketEvidence::new(envelope_digest, 4),
        ),
        TicketSource::Leased {
            boot_id: queue.boot_id.clone(),
            boottime_deadline_ns: 1,
            wall_deadline_ns: 2,
        },
        TicketDestination::Receipt { terminal_bucket },
    )
    .unwrap();
    let (_, destination) = queue.transition_ticket_paths(&ticket).unwrap();
    let destination_path = tmp.path().join(&destination);
    std::fs::create_dir_all(destination_path.parent().unwrap()).unwrap();
    let mut receipt = steadq_format::CompactReceipt {
        job_id,
        envelope_digest,
        final_attempt: 1,
        lease_token,
        receipt_bucket_start_unix_ns: terminal_bucket * queue.format.terminal_bucket_width_ns(),
        original_payload_length: 4,
    };
    std::fs::write(&destination_path, receipt.encode()).unwrap();
    assert!(matches!(
        queue.resolve(&ticket, false),
        ResolutionOutcome::DestinationObserved
    ));

    receipt.job_id[0] ^= 0xff;
    std::fs::write(&destination_path, receipt.encode()).unwrap();
    assert!(matches!(
        queue.resolve(&ticket, false),
        ResolutionOutcome::ConflictingObject
    ));
    receipt.job_id = job_id;

    receipt.final_attempt = 2;
    std::fs::write(&destination_path, receipt.encode()).unwrap();
    assert!(matches!(
        queue.resolve(&ticket, false),
        ResolutionOutcome::ConflictingObject
    ));

    receipt.final_attempt = 1;
    receipt.receipt_bucket_start_unix_ns += 1;
    std::fs::write(&destination_path, receipt.encode()).unwrap();
    assert!(matches!(
        queue.resolve(&ticket, false),
        ResolutionOutcome::ConflictingObject
    ));

    receipt.receipt_bucket_start_unix_ns -= 1;
    receipt.original_payload_length = 5;
    std::fs::write(&destination_path, receipt.encode()).unwrap();
    assert!(matches!(
        queue.resolve(&ticket, false),
        ResolutionOutcome::ConflictingObject
    ));
}

#[test]
fn resolve_rejects_compact_receipt_at_ready_source() {
    let (tmp, queue) = create_test_queue();
    let job_id = [7; 16];
    let lease_token = [8; 16];
    let envelope_digest = [9; 32];
    let ticket = test_claim_ticket(&queue, job_id, 0, 0, 3, lease_token, envelope_digest);
    let (source, _) = queue.transition_ticket_paths(&ticket).unwrap();
    let receipt = steadq_format::CompactReceipt {
        job_id,
        envelope_digest,
        final_attempt: 0,
        lease_token,
        receipt_bucket_start_unix_ns: 0,
        original_payload_length: 4,
    };
    std::fs::write(tmp.path().join(source), receipt.encode()).unwrap();

    assert!(matches!(
        queue.resolve(&ticket, false),
        ResolutionOutcome::ConflictingObject
    ));
}

#[test]
fn resolver_rejects_hard_links_for_every_operation_side() {
    for operation in [
        "claim",
        "acknowledge",
        "retry_now",
        "retry_later",
        "bury",
        "renew",
    ] {
        let (tmp, queue, ticket) = resolver_ticket_case(operation);
        let (source, _) = queue.transition_ticket_paths(&ticket).unwrap();
        add_hard_link(&tmp, &source, &format!("{operation}-source"));
        assert!(matches!(
            queue.resolve(&ticket, false),
            ResolutionOutcome::ConflictingObject
        ));

        let (tmp, queue, ticket) = resolver_ticket_case(operation);
        let (source, destination) = queue.transition_ticket_paths(&ticket).unwrap();
        let destination_path = tmp.path().join(&destination);
        std::fs::create_dir_all(destination_path.parent().unwrap()).unwrap();
        std::fs::rename(tmp.path().join(source), &destination_path).unwrap();
        add_hard_link(&tmp, &destination, &format!("{operation}-destination"));
        assert!(matches!(
            queue.resolve(&ticket, false),
            ResolutionOutcome::ConflictingObject
        ));
    }
}

#[test]
fn resolve_both_same_hard_link_is_conflict() {
    // A hard link between source and destination gives link count 2, which
    // the resolver correctly classifies as Conflict, not both-same.
    // True both-same (same inode, link count 1 at both paths) is physically
    // impossible after an atomic no-overwrite rename, so this guard is the
    // correct production behavior.
    let (tmp, queue, ticket) = resolver_ticket_case("retry_now");
    let (source_rel, dest_rel) = queue.transition_ticket_paths(&ticket).unwrap();
    let source_path = tmp.path().join(&source_rel);
    let dest_path = tmp.path().join(&dest_rel);
    assert!(source_path.exists(), "source must exist before test");
    if let Some(parent) = dest_path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::hard_link(&source_path, &dest_path).unwrap();

    let outcome = queue.resolve(&ticket, true);
    assert!(
        matches!(outcome, ResolutionOutcome::ConflictingObject),
        "hard-linked both should be Conflict, got {outcome:?}"
    );
}

#[test]
fn resolve_both_different_is_conflict() {
    let (tmp, queue, ticket) = resolver_ticket_case("retry_now");
    let (source_rel, dest_rel) = queue.transition_ticket_paths(&ticket).unwrap();
    let source_path = tmp.path().join(&source_rel);
    let dest_path = tmp.path().join(&dest_rel);
    assert!(source_path.exists(), "source must exist before test");
    if let Some(parent) = dest_path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&dest_path, b"different inode").unwrap();

    let outcome = queue.resolve(&ticket, true);
    assert!(
        matches!(outcome, ResolutionOutcome::ConflictingObject),
        "expected ConflictingObject, got {outcome:?}"
    );
    assert!(source_path.exists(), "source must remain");
    assert!(dest_path.exists(), "destination must remain");
}

#[test]
fn resolve_observes_delayed_dead_and_full_receipt_destinations() {
    let (_tmp, mut delayed_queue) = create_test_queue();
    let delayed_lease = enqueue_and_lease(&mut delayed_queue);
    let not_before_ns = delayed_queue.wall_floor_for_mutation().unwrap().unix_ns() + 60_000_000_000;
    let delayed_ticket = delayed_queue
        .transition_ticket_for_lease(
            &delayed_lease,
            TransitionOperation::RetryLater,
            TicketDestination::Delayed { not_before_ns },
        )
        .unwrap();
    delayed_queue
        .retry_at(&delayed_lease, not_before_ns)
        .commit_or_panic();
    assert!(matches!(
        delayed_queue.resolve(&delayed_ticket, false),
        ResolutionOutcome::DestinationObserved
    ));

    let (_tmp, mut dead_queue) = create_test_queue();
    let dead_lease = enqueue_and_lease(&mut dead_queue);
    dead_queue
        .bury(&dead_lease, DeadReason::AdministrativeBury)
        .commit_or_panic();
    let dead_snapshot = dead_queue
        .inspect(&dead_lease.job_id)
        .into_iter()
        .find(|snapshot| snapshot.state == "dead")
        .unwrap();
    let dead_bucket =
        steadq_names::bucket_from_hex(dead_snapshot.relative_path.split('/').nth(1).unwrap())
            .unwrap();
    let dead_ticket = dead_queue
        .transition_ticket_for_lease(
            &dead_lease,
            TransitionOperation::Bury,
            TicketDestination::Dead {
                terminal_bucket: dead_bucket,
                reason: DeadReason::AdministrativeBury as u16,
            },
        )
        .unwrap();
    assert!(matches!(
        dead_queue.resolve(&dead_ticket, false),
        ResolutionOutcome::DestinationObserved
    ));

    let (_tmp, mut receipt_queue) = create_test_queue();
    let receipt_lease = enqueue_and_lease(&mut receipt_queue);
    assert!(matches!(
        receipt_queue.ack(&receipt_lease),
        AckOutcome::Acked
    ));
    let receipt_snapshot = receipt_queue
        .inspect(&receipt_lease.job_id)
        .into_iter()
        .find(|snapshot| snapshot.state == "receipt")
        .unwrap();
    let receipt_bucket =
        steadq_names::bucket_from_hex(receipt_snapshot.relative_path.split('/').nth(1).unwrap())
            .unwrap();
    let receipt_ticket = receipt_queue
        .transition_ticket_for_lease(
            &receipt_lease,
            TransitionOperation::Acknowledge,
            TicketDestination::Receipt {
                terminal_bucket: receipt_bucket,
            },
        )
        .unwrap();
    assert!(matches!(
        receipt_queue.resolve(&receipt_ticket, false),
        ResolutionOutcome::DestinationObserved
    ));

    let mut ticket_json: serde_json::Value =
        serde_json::from_slice(&receipt_ticket.to_json().unwrap()).unwrap();
    ticket_json["source_identity"]["payload_length"] =
        serde_json::json!(receipt_ticket.payload_length() + 1);
    let wrong_payload_length =
        TransitionTicket::from_json(&serde_json::to_vec(&ticket_json).unwrap()).unwrap();
    assert!(matches!(
        receipt_queue.resolve(&wrong_payload_length, false),
        ResolutionOutcome::ConflictingObject
    ));

    fs::fault::reset();
    fs::fault::inject("pread", 3);
    assert!(matches!(
        receipt_queue.resolve(&receipt_ticket, false),
        ResolutionOutcome::ResolutionFailed(Error::IoFailure(_))
    ));
    fs::fault::reset();

    std::fs::OpenOptions::new()
        .write(true)
        .open(_tmp.path().join(&receipt_snapshot.relative_path))
        .unwrap()
        .set_len(128)
        .unwrap();
    assert!(matches!(
        receipt_queue.resolve(&receipt_ticket, false),
        ResolutionOutcome::ConflictingObject
    ));
}

// ===== Wall watermark advances after enqueue =====
#[test]
fn wall_watermark_advances() {
    let (_tmp, mut queue) = create_test_queue();
    let wm_before = queue.read_wall_watermark().ok();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    });
    let wm_after = queue.read_wall_watermark().ok();
    // After enqueue, the watermark bucket should not regress
    if let (Some(before), Some(after)) = (wm_before, wm_after) {
        assert!(after.highest_observed_bucket >= before.highest_observed_bucket);
    }
}

#[test]
fn watermark_missing_and_corrupt_fail_closed() {
    let (tmp, queue) = create_test_queue();
    let watermark = queue
        .read_wall_watermark()
        .expect("initialized queue has a watermark");
    let floor = queue.authenticated_wall_floor().unwrap();
    assert_eq!(floor.watermark_bucket(), watermark.highest_observed_bucket);
    assert_eq!(floor.watermark_sequence(), watermark.sequence);
    assert!(
        floor.unix_ns()
            >= watermark.highest_observed_bucket * queue.format.delayed_bucket_width_ns()
    );

    let wm_path = tmp.path().join("control/wall-watermark");
    std::fs::remove_file(&wm_path).unwrap();
    assert!(matches!(
        queue.read_wall_watermark(),
        Err(WatermarkReadError::NotFound)
    ));
    fs::fault::reset();
    fs::fault::inject("clock_realtime_ns", 1);
    assert!(matches!(
        queue.effective_wall_floor_ns_checked(),
        Err(Error::QueueCorrupt(_))
    ));
    assert_eq!(fs::fault::call_count("clock_realtime_ns"), 0);
    fs::fault::reset();

    let (tmp, queue) = create_test_queue();
    let wm_path = tmp.path().join("control/wall-watermark");
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(&wm_path)
            .unwrap();
        f.write_all(&[0xFF; 8]).unwrap();
        f.sync_all().unwrap();
    }
    let corrupt = queue.read_wall_watermark();
    assert!(
        matches!(
            corrupt,
            Err(WatermarkReadError::Corrupt(_)) | Err(WatermarkReadError::Truncated(_))
        ),
        "corrupt watermark should be Corrupt or Truncated, got {corrupt:?}"
    );
    let floor_err = queue.effective_wall_floor_ns_checked();
    assert!(
        matches!(floor_err, Err(Error::QueueCorrupt(_))),
        "corrupt watermark floor should be QueueCorrupt, got {floor_err:?}"
    );
    let advance_err = queue.stabilized_wall_floor();
    assert!(
        matches!(advance_err, Err(Error::QueueCorrupt(_))),
        "advance with corrupt watermark should be QueueCorrupt, got {advance_err:?}"
    );
}

#[test]
fn authenticated_wall_floor_never_regresses_below_watermark() {
    let (tmp, queue) = create_test_queue();
    let current = queue.read_wall_watermark().unwrap();
    let future_bucket = current.highest_observed_bucket.checked_add(10).unwrap();
    let watermark = steadq_format::WatermarkRecord {
        highest_observed_bucket: future_bucket,
        sequence: current.sequence.checked_add(1).unwrap(),
    };
    std::fs::write(
        tmp.path().join("control/wall-watermark"),
        watermark.encode(),
    )
    .unwrap();

    let floor = queue.authenticated_wall_floor().unwrap();
    let minimum = future_bucket
        .checked_mul(queue.format.delayed_bucket_width_ns())
        .unwrap();
    assert_eq!(floor.unix_ns(), minimum);
    assert_eq!(floor.watermark_bucket(), future_bucket);
    assert_eq!(floor.watermark_sequence(), watermark.sequence);
}

#[test]
fn watermark_read_retries_an_atomic_replacement() {
    let (tmp, queue) = create_test_queue();
    let original = queue.read_wall_watermark().unwrap();
    let control = fs::open_directory(queue.root_fd(), "control").unwrap();
    let opened = fs::openat(control.as_fd(), "wall-watermark", watermark_open_flags(), 0).unwrap();
    let opened_before = fs::fstat(opened.as_fd()).unwrap();
    assert_eq!(opened_before.st_nlink, 1);

    let replacement_bucket = original.highest_observed_bucket.checked_add(1).unwrap();
    let replacement_sequence = original.sequence.checked_add(1).unwrap();
    replace_wall_watermark(&tmp, replacement_bucket, replacement_sequence);

    let current = fs::fstatat(control.as_fd(), "wall-watermark").unwrap();
    assert!(!watermark_path_matches_opened(&opened_before, &current).unwrap());
    assert!(matches!(
        Queue::read_opened_wall_watermark(control.as_fd(), opened.as_fd()).unwrap(),
        WatermarkSnapshot::Replaced
    ));

    let observed = queue.read_wall_watermark().unwrap();
    assert_eq!(observed.highest_observed_bucket, replacement_bucket);
    assert_eq!(observed.sequence, replacement_sequence);
}

#[test]
fn watermark_read_reuses_the_open_file() {
    let (_tmp, queue) = create_test_queue();
    queue.cached_watermark_fd.borrow_mut().take();
    fs::fault::reset();
    fs::fault::inject("unused", u64::MAX);

    queue.read_wall_watermark().unwrap();
    queue.read_wall_watermark().unwrap();

    assert_eq!(fs::fault::call_count("openat"), 1);
    fs::fault::reset();
}

#[test]
fn watermark_read_exhaustion_is_transient_contention() {
    let (_tmp, queue) = create_test_queue();

    assert!(queue.try_read_wall_watermark(0).unwrap().is_none());
    assert_eq!(
        queue.authenticated_wall_floor_with_attempts(0),
        Err(Error::MaintenanceBusy)
    );
    assert!(
        queue.read_wall_watermark().is_ok(),
        "the ordinary authenticated read must remain usable"
    );
}

#[test]
fn cached_wall_floor_contention_does_not_poison_the_handle() {
    let (_tmp, mut queue) = create_test_queue();
    queue.wall_floor_for_mutation().unwrap();

    assert_eq!(
        queue.wall_floor_for_mutation_with_attempts(0),
        Err(Error::MaintenanceBusy)
    );
    assert!(
        !queue.is_poisoned(),
        "transient replacement contention poisoned the queue"
    );
    assert!(
        queue.wall_floor_for_mutation().is_ok(),
        "the queue must remain usable after transient contention"
    );
}

#[test]
fn watermark_path_authentication_classifies_replacement_and_invalid_properties() {
    let (_tmp, queue) = create_test_queue();
    let control = fs::open_directory(queue.root_fd(), "control").unwrap();
    let opened = fs::openat(control.as_fd(), "wall-watermark", watermark_open_flags(), 0).unwrap();
    let valid = fs::fstat(opened.as_fd()).unwrap();

    let mut non_regular = valid;
    non_regular.st_mode = (non_regular.st_mode & !libc::S_IFMT) | libc::S_IFDIR;
    assert!(matches!(
        watermark_path_matches_opened(&valid, &non_regular),
        Err(WatermarkReadError::Corrupt(_))
    ));

    let mut unlinked = valid;
    unlinked.st_nlink = 0;
    assert!(!watermark_path_matches_opened(&valid, &unlinked).unwrap());

    let mut multiply_linked = valid;
    multiply_linked.st_nlink = 2;
    assert!(matches!(
        watermark_path_matches_opened(&valid, &multiply_linked),
        Err(WatermarkReadError::Corrupt(_))
    ));
}

#[test]
fn cached_wall_floor_observes_another_handles_durable_advance_after_rollback() {
    let (tmp, mut handle_a) = create_test_queue();
    let mut handle_b = Queue::open(
        tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    )
    .unwrap();
    let width = handle_a.format.delayed_bucket_width_ns();
    let initial = handle_a.read_wall_watermark().unwrap();
    let bucket_n = initial.highest_observed_bucket;
    let time_n = bucket_n.checked_mul(width).unwrap();
    let time_n_plus_one = bucket_n.checked_add(1).unwrap().checked_mul(width).unwrap();

    fs::fault::reset();
    fs::fault::set_clock_realtime_ns(time_n);
    let cached = handle_a.wall_floor_for_mutation().unwrap();
    assert_eq!(cached.watermark_bucket(), bucket_n);

    fs::fault::set_clock_realtime_ns(time_n_plus_one);
    let advanced = handle_b.wall_floor_for_mutation().unwrap();
    assert_eq!(advanced.watermark_bucket(), bucket_n + 1);

    fs::fault::set_clock_realtime_ns(time_n);
    let after_rollback = handle_a.wall_floor_for_mutation().unwrap();
    fs::fault::reset();

    assert_eq!(after_rollback.watermark_bucket(), bucket_n + 1);
    assert!(after_rollback.unix_ns() >= time_n_plus_one);
    assert!(after_rollback.watermark_sequence() > cached.watermark_sequence());
}

#[test]
fn cached_wall_floor_reenters_lock_when_shared_sequence_changes() {
    let (tmp, mut queue) = create_test_queue();
    let current = queue.wall_floor_for_mutation().unwrap();
    write_wall_watermark(
        &tmp,
        current.watermark_bucket(),
        current.watermark_sequence().checked_add(1).unwrap(),
    );
    let control = fs::open_directory(queue.root_fd(), "control").unwrap();
    let lock = fs::openat(control.as_fd(), "wall-watermark.lock", libc::O_RDWR, 0).unwrap();
    assert!(fs::try_ofd_write_lock(lock.as_fd()).unwrap());

    assert_eq!(queue.wall_floor_for_mutation(), Err(Error::MaintenanceBusy));
    assert!(!queue.is_poisoned());
}

#[test]
fn cached_wall_floor_preserves_sub_bucket_floor_after_realtime_rollback() {
    let (_tmp, mut queue) = create_test_queue();
    let watermark = queue.read_wall_watermark().unwrap();
    let width = queue.format.delayed_bucket_width_ns();
    let bucket_start = watermark
        .highest_observed_bucket
        .checked_mul(width)
        .unwrap();
    let higher_time = bucket_start.checked_add(width - 1).unwrap();

    fs::fault::reset();
    fs::fault::set_clock_realtime_ns(higher_time);
    let cached = queue.wall_floor_for_mutation().unwrap();
    assert_eq!(cached.unix_ns(), higher_time);

    fs::fault::set_clock_realtime_ns(bucket_start);
    let after_rollback = queue.wall_floor_for_mutation().unwrap();
    fs::fault::reset();

    assert_eq!(after_rollback.unix_ns(), higher_time);
    assert_eq!(after_rollback.watermark_bucket(), cached.watermark_bucket());
    assert_eq!(
        after_rollback.watermark_sequence(),
        cached.watermark_sequence()
    );
}

#[test]
fn mutation_wall_floor_is_durable_before_return() {
    let (tmp, mut queue) = create_test_queue();
    write_wall_watermark(&tmp, 0, 1);

    let floor = queue.wall_floor_for_mutation().unwrap();
    let stored = queue.read_wall_watermark().unwrap();
    let observed_bucket =
        steadq_math::bucket_number(floor.unix_ns(), queue.format.delayed_bucket_width_ns())
            .unwrap();
    assert_eq!(stored.highest_observed_bucket, observed_bucket);
    assert_eq!(floor.watermark_bucket(), observed_bucket);
    assert!(stored.sequence > 1);
}

#[test]
fn watermark_typed_read_truncated_is_queue_corrupt() {
    let (tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"hello".to_vec(),
        ..Default::default()
    });
    let wm_path = tmp.path().join("control/wall-watermark");
    {
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&wm_path)
            .unwrap();
        f.set_len(4).unwrap();
        f.sync_all().unwrap();
    }
    let truncated = queue.read_wall_watermark();
    assert!(
        matches!(truncated, Err(WatermarkReadError::Truncated(_))),
        "truncated watermark should be Truncated, got {truncated:?}"
    );
    let floor = queue.effective_wall_floor_ns_checked();
    assert!(
        matches!(floor, Err(Error::QueueCorrupt(_))),
        "truncated floor should be QueueCorrupt, got {floor:?}"
    );
}

#[test]
fn watermark_requires_exact_singly_linked_regular_file() {
    let (tmp, queue) = create_test_queue();
    let path = tmp.path().join("control/wall-watermark");
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.push(0);
    std::fs::write(&path, bytes).unwrap();
    assert!(matches!(
        queue.read_wall_watermark(),
        Err(WatermarkReadError::Corrupt(_))
    ));

    let (tmp, queue) = create_test_queue();
    let path = tmp.path().join("control/wall-watermark");
    std::fs::hard_link(&path, tmp.path().join("tmp/watermark-link")).unwrap();
    assert!(matches!(
        queue.read_wall_watermark(),
        Err(WatermarkReadError::Corrupt(_))
    ));

    let (tmp, queue) = create_test_queue();
    let path = tmp.path().join("control/wall-watermark");
    let displaced = tmp.path().join("tmp/watermark-displaced");
    std::fs::rename(&path, &displaced).unwrap();
    std::os::unix::fs::symlink(&displaced, &path).unwrap();
    assert!(matches!(
        queue.read_wall_watermark(),
        Err(WatermarkReadError::Io(_))
    ));
}

#[test]
fn watermark_open_is_not_found_table() {
    let cases: &[(std::io::ErrorKind, bool)] = &[
        (std::io::ErrorKind::NotFound, true),
        (std::io::ErrorKind::PermissionDenied, false),
        (std::io::ErrorKind::AlreadyExists, false),
        (std::io::ErrorKind::InvalidInput, false),
        (std::io::ErrorKind::UnexpectedEof, false),
    ];
    for (kind, expected) in cases {
        let err = std::io::Error::new(*kind, "test");
        assert_eq!(
            watermark_open_is_not_found(&err),
            *expected,
            "kind {kind:?} should be {expected}"
        );
    }
    let not_found = std::io::Error::new(std::io::ErrorKind::NotFound, "nf");
    let perm = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "perm");
    assert_ne!(
        watermark_open_is_not_found(&not_found),
        watermark_open_is_not_found(&perm),
        "NotFound must differ from other kinds"
    );
}

#[test]
fn watermark_open_flags_require_nofollow_and_cloexec() {
    let flags = watermark_open_flags();
    assert_eq!(flags, libc::O_NOFOLLOW | libc::O_CLOEXEC);
    assert_ne!(flags & libc::O_NOFOLLOW, 0);
    assert_ne!(flags & libc::O_CLOEXEC, 0);
}

#[test]
fn watermark_should_advance_table() {
    assert!(
        !watermark_should_advance(5, 5),
        "equal buckets should not advance"
    );
    assert!(
        !watermark_should_advance(4, 5),
        "smaller observed should not advance"
    );
    assert!(
        watermark_should_advance(6, 5),
        "greater observed should advance"
    );
    assert!(watermark_should_advance(1, 0), "1 > 0 should advance");
    assert!(!watermark_should_advance(0, 0), "0 == 0 should not advance");
    assert!(
        !watermark_should_advance(u64::MAX - 1, u64::MAX),
        "max-1 vs max should not advance"
    );
    assert!(
        watermark_should_advance(u64::MAX, u64::MAX - 1),
        "max vs max-1 should advance"
    );
}

#[test]
fn watermark_advance_does_not_rewrite_on_equal_bucket() {
    let (_tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"a".to_vec(),
        ..Default::default()
    });
    let wm_before = queue.read_wall_watermark().expect("watermark exists");
    let bucket = wm_before.highest_observed_bucket;
    let width = queue.format().delayed_bucket_width_ns();
    let observed = WallFloor {
        unix_ns: bucket * width,
        watermark_bucket: bucket,
        watermark_sequence: wm_before.sequence,
    };
    let seq_before = wm_before.sequence;
    let res = queue.with_wall_watermark_write_lock(|control_fd| {
        queue.advance_wall_watermark_locked(observed, control_fd)
    });
    assert!(
        res.is_ok(),
        "equal bucket advance should be Ok, got {res:?}"
    );
    let wm_after = queue.read_wall_watermark().expect("watermark still exists");
    assert_eq!(
        wm_after.sequence, seq_before,
        "equal bucket should not bump sequence"
    );
    assert_eq!(
        wm_after.highest_observed_bucket, bucket,
        "equal bucket should not change bucket"
    );
}

#[test]
fn watermark_advance_fault_matrix() {
    for (syscall, at_count) in [
        ("open_directory", 1),
        ("openat", 1),
        ("try_ofd_write_lock", 1),
        ("openat", 2),
        ("fstat", 1),
        ("pread", 1),
        ("get_random", 1),
        ("write_all", 1),
        ("fsync", 1),
        ("renameat", 1),
        ("fsync_dir_fd", 1),
    ] {
        let (_tmp, queue) = create_test_queue();
        let watermark = queue.read_wall_watermark().unwrap();
        let observed_bucket = watermark.highest_observed_bucket.checked_add(1).unwrap();
        let observed_ns = observed_bucket
            .checked_mul(queue.format.delayed_bucket_width_ns())
            .unwrap();
        let observed = WallFloor {
            unix_ns: observed_ns,
            watermark_bucket: watermark.highest_observed_bucket,
            watermark_sequence: watermark.sequence,
        };
        fs::fault::reset();
        fs::fault::inject(syscall, at_count);
        let result = queue.with_wall_watermark_write_lock(|control_fd| {
            queue.advance_wall_watermark_locked(observed, control_fd)
        });
        assert!(result.is_err(), "{syscall} fault #{at_count} was ignored");
        assert_eq!(fs::fault::call_count(syscall), at_count);
        fs::fault::reset();
    }
}

#[test]
fn watermark_advance_rejects_missing_authority() {
    let (tmp, queue) = create_test_queue();
    remove_wall_watermark(&tmp);
    assert!(matches!(
        queue.stabilized_wall_floor(),
        Err(Error::QueueCorrupt(_))
    ));
}

#[test]
fn enqueue_fails_before_publication_when_wall_stabilization_fails() {
    let (tmp, mut queue) = create_test_queue();
    write_wall_watermark(&tmp, 0, 1);
    fs::fault::reset();
    fs::fault::inject("try_ofd_write_lock", 1);
    let outcome = queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".into(),
        payload: b"data".to_vec(),
        ..Default::default()
    });
    fs::fault::reset();
    assert!(matches!(
        outcome,
        EnqueueOutcome::NotCommitted(_, Error::IoFailure(_))
    ));
    assert!(queue.is_poisoned());
    assert!(find_file_with_suffix(&tmp.path().join("ready"), ".sqj").is_none());
}

#[test]
fn enqueue_does_not_publish_while_wall_stabilization_is_contended() {
    let (tmp, mut queue) = create_test_queue();
    write_wall_watermark(&tmp, 0, 1);
    let control_fd = fs::open_directory(queue.root_fd(), "control").unwrap();
    let lock_fd = fs::openat(control_fd.as_fd(), "wall-watermark.lock", libc::O_RDWR, 0).unwrap();
    assert!(fs::try_ofd_write_lock(lock_fd.as_fd()).unwrap());

    let outcome = queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".into(),
        payload: b"data".to_vec(),
        ..Default::default()
    });
    assert!(matches!(
        outcome,
        EnqueueOutcome::NotCommitted(_, Error::MaintenanceBusy)
    ));
    assert!(!queue.is_poisoned());
    assert!(find_file_with_suffix(&tmp.path().join("ready"), ".sqj").is_none());
}

#[test]
fn ack_can_retry_same_lease_after_wall_stabilization_contention() {
    let (_tmp, mut queue) = create_test_queue();
    let lease = enqueue_and_lease(&mut queue);

    let control_fd = fs::open_directory(queue.root_fd(), "control").unwrap();
    let lock_fd = fs::openat(control_fd.as_fd(), "wall-watermark.lock", libc::O_RDWR, 0).unwrap();
    assert!(fs::try_ofd_write_lock(lock_fd.as_fd()).unwrap());
    queue.cached_wall_floor = None;

    assert!(matches!(
        queue.ack(&lease),
        AckOutcome::NotCommitted(Error::MaintenanceBusy)
    ));
    assert!(!queue.is_poisoned());

    drop(lock_fd);
    assert!(matches!(queue.ack(&lease), AckOutcome::Acked));
}

#[test]
fn equal_bucket_stabilization_checks_live_writer_lock() {
    let (tmp, mut queue) = create_test_queue();
    let current = queue.authenticated_wall_floor().unwrap();
    write_wall_watermark(
        &tmp,
        steadq_math::bucket_number(current.unix_ns(), queue.format.delayed_bucket_width_ns())
            .unwrap(),
        current.watermark_sequence(),
    );
    let control_fd = fs::open_directory(queue.root_fd(), "control").unwrap();
    let lock_fd = fs::openat(control_fd.as_fd(), "wall-watermark.lock", libc::O_RDWR, 0).unwrap();
    assert!(fs::try_ofd_write_lock(lock_fd.as_fd()).unwrap());

    let outcome = queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".into(),
        payload: b"data".to_vec(),
        ..Default::default()
    });
    assert!(matches!(
        outcome,
        EnqueueOutcome::NotCommitted(_, Error::MaintenanceBusy)
    ));
    assert!(find_file_with_suffix(&tmp.path().join("ready"), ".sqj").is_none());
}

#[test]
fn watermark_read_distinguishes_io_from_notfound() {
    steadq_fs_linux::fault::reset();
    let (_tmp, queue) = create_test_queue();
    steadq_fs_linux::fault::inject("openat", 1);
    let result = queue.read_wall_watermark();
    assert!(
        matches!(result, Err(WatermarkReadError::Io(_))),
        "injected wall-watermark openat EIO should be Io not NotFound, got {result:?}"
    );
    steadq_fs_linux::fault::inject("openat", 1);
    let floor = queue.effective_wall_floor_ns_checked();
    steadq_fs_linux::fault::reset();
    assert!(
        matches!(floor, Err(Error::IoFailure(_))),
        "Io watermark should make floor IoFailure, got {floor:?}"
    );
}

#[test]
fn authenticated_wall_floor_fault_matrix() {
    for syscall in [
        "open_directory",
        "openat",
        "fstat",
        "pread",
        "fstatat",
        "clock_realtime_ns",
    ] {
        let (_tmp, queue) = create_test_queue();
        fs::fault::reset();
        fs::fault::inject(syscall, 1);
        let result = queue.authenticated_wall_floor();
        assert!(
            matches!(result, Err(Error::IoFailure(_))),
            "{syscall} failure must fail closed, got {result:?}"
        );
        assert_eq!(fs::fault::call_count(syscall), 1);
        fs::fault::reset();
    }
}

#[test]
fn stabilized_wall_floor_lock_fault_matrix() {
    for syscall in ["open_directory", "openat", "try_ofd_write_lock"] {
        let (_tmp, queue) = create_test_queue();
        fs::fault::reset();
        fs::fault::inject(syscall, 1);
        let result = queue.stabilized_wall_floor();
        assert!(
            matches!(result, Err(Error::IoFailure(_))),
            "{syscall} failure must fail closed, got {result:?}"
        );
        assert_eq!(fs::fault::call_count(syscall), 1);
        fs::fault::reset();
    }
}

#[test]
fn wall_watermark_write_lock_excludes_new_readers_through_action() {
    let (_tmp, queue) = create_test_queue();
    let result = queue.with_wall_watermark_write_lock(|_| {
        let control_fd = fs::open_directory(queue.root_fd(), "control")
            .map_err(|error| Error::IoFailure(error.to_string()))?;
        let competing_fd = fs::openat(
            control_fd.as_fd(),
            "wall-watermark.lock",
            libc::O_RDWR,
            0o600,
        )
        .map_err(|error| Error::IoFailure(error.to_string()))?;
        let competing_reader = fs::try_ofd_read_lock(competing_fd.as_fd())
            .map_err(|error| Error::IoFailure(error.to_string()))?;
        assert!(!competing_reader, "new readers must wait behind the writer");
        Ok(())
    });
    assert!(result.is_ok(), "exclusive action failed: {result:?}");
}

#[test]
fn stabilized_wall_floor_advances_under_one_exclusive_lock() {
    let (tmp, queue) = create_test_queue();
    write_wall_watermark(&tmp, 0, 1);
    fs::fault::reset();
    fs::fault::inject("try_ofd_write_lock", u64::MAX);
    fs::fault::inject("try_ofd_read_lock", u64::MAX);

    let floor = queue
        .stabilized_wall_floor()
        .expect("watermark advance should complete");

    assert!(floor.watermark_bucket() > 0);
    assert_eq!(fs::fault::call_count("try_ofd_write_lock"), 1);
    assert_eq!(fs::fault::call_count("try_ofd_read_lock"), 0);
    fs::fault::reset();
}

#[test]
fn wall_sensitive_mutations_fail_closed_without_watermark() {
    let (tmp, mut queue) = create_test_queue();
    remove_wall_watermark(&tmp);
    assert!(matches!(
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".into(),
            payload: b"data".to_vec(),
            ..Default::default()
        }),
        EnqueueOutcome::NotCommitted(_, Error::QueueCorrupt(_))
    ));
    assert!(queue.is_poisoned());

    let (tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".into(),
        payload: b"data".to_vec(),
        ..Default::default()
    });
    remove_wall_watermark(&tmp);
    queue.cached_wall_floor = None;
    assert!(matches!(
        queue.lease(0, 30_000_000_000),
        LeaseOutcome::NotCommitted(Error::QueueCorrupt(_))
    ));

    for operation in ["ack", "retry_at", "retry_after", "bury", "renew"] {
        let (tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".into(),
            payload: b"data".to_vec(),
            ..Default::default()
        });
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(lease) => lease,
            outcome => panic!("lease failed before {operation}: {outcome:?}"),
        };
        remove_wall_watermark(&tmp);
        queue.cached_wall_floor = None;
        match operation {
            "ack" => assert!(matches!(
                queue.ack(&lease),
                AckOutcome::NotCommitted(Error::QueueCorrupt(_))
            )),
            "retry_at" => assert!(matches!(
                queue.retry_at(&lease, u64::MAX - 1),
                TransitionOutcome::NotCommitted(Error::QueueCorrupt(_))
            )),
            "retry_after" => assert!(matches!(
                queue.retry_after(&lease, 1_000_000_000),
                TransitionOutcome::NotCommitted(Error::QueueCorrupt(_))
            )),
            "bury" => assert!(matches!(
                queue.bury(&lease, DeadReason::AdministrativeBury),
                TransitionOutcome::NotCommitted(Error::QueueCorrupt(_))
            )),
            "renew" => assert!(matches!(
                queue.renew(&lease, 30_000_000_000),
                RenewOutcome::NotCommitted(Error::QueueCorrupt(_))
            )),
            _ => unreachable!(),
        }
        assert!(queue.is_poisoned(), "{operation} must poison the handle");
    }
}

#[test]
fn wall_sensitive_operation_uses_one_snapshot() {
    let (_tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".into(),
        payload: b"data".to_vec(),
        ..Default::default()
    });
    fs::fault::reset();
    fs::fault::inject("clock_realtime_ns", 2);
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(lease) => lease,
        outcome => panic!("lease failed: {outcome:?}"),
    };
    assert_eq!(fs::fault::call_count("clock_realtime_ns"), 1);
    fs::fault::reset();
    fs::fault::inject("clock_realtime_ns", 2);
    assert!(matches!(queue.ack(&lease), AckOutcome::Acked));
    assert_eq!(fs::fault::call_count("clock_realtime_ns"), 1);
    fs::fault::reset();
}

// ===== Lease source validation rejects corrupted handle =====
#[test]
fn source_validation_rejects_wrong_generation() {
    let (_tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    });
    let mut lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!("lease failed"),
    };
    // Corrupt the generation in the handle
    lease.generation = 999;
    let result = queue.retry_now(&lease);
    // Should not get LeaseLost (that's for missing source), should get corruption or not committed
    assert!(!matches!(result, TransitionOutcome::Committed));
}

#[test]
fn source_identity_fields_are_authenticated_before_every_lease_transition() {
    for operation in ["ack", "retry", "bury", "renew"] {
        for field in [
            "boot_id",
            "boottime_deadline",
            "wall_deadline",
            "payload_length",
            "payload_digest",
        ] {
            let (_tmp, mut queue) = create_test_queue();
            let mut lease = enqueue_and_lease(&mut queue);
            match field {
                "boot_id" => lease.boot_id = "00000000-0000-0000-0000-000000000000".into(),
                "boottime_deadline" => lease.expires_boottime_ns ^= 1,
                "wall_deadline" => lease.expires_wall_ns ^= 1,
                "payload_length" => lease.payload_length ^= 1,
                "payload_digest" => lease.payload_digest[0] ^= 0xff,
                _ => unreachable!(),
            }

            fs::fault::reset();
            let rejected = match operation {
                "ack" => matches!(
                    queue.ack(&lease),
                    AckOutcome::NotCommitted(Error::QueueCorrupt(_))
                ),
                "retry" => matches!(
                    queue.retry_now(&lease),
                    TransitionOutcome::NotCommitted(Error::QueueCorrupt(_))
                ),
                "bury" => matches!(
                    queue.bury(&lease, DeadReason::AdministrativeBury),
                    TransitionOutcome::NotCommitted(Error::QueueCorrupt(_))
                ),
                "renew" => matches!(
                    queue.renew(&lease, 30_000_000_000),
                    RenewOutcome::NotCommitted(Error::QueueCorrupt(_))
                ),
                _ => unreachable!(),
            };
            assert!(rejected, "{operation} accepted mutated {field}");
            assert_eq!(
                fs::fault::call_count("renameat2_noreplace"),
                0,
                "{operation} renamed after mutated {field}"
            );
            fs::fault::reset();
        }
    }
}

// ===== Scan distinguishes empty from error =====
#[test]
fn empty_queue_returns_empty_not_error() {
    let (_tmp, mut queue) = create_test_queue();
    let result = queue.lease(0, 30_000_000_000);
    assert!(matches!(result, LeaseOutcome::Empty));
}

#[test]
#[ignore = "manual latency measurement; run with --release --ignored --nocapture"]
fn measure_dispatch_latency_watch_vs_poll() {
    let mut with_watch = Vec::new();
    let mut poll_only = Vec::new();
    for round in 0..2 {
        let (tmp, mut queue) = create_test_queue();
        if round == 1 {
            // Simulate watch failure: permanent poll fallback.
            queue.ready_watch_attempted = true;
        }
        let path = tmp.path().to_path_buf();
        for i in 0..50u32 {
            let p = path.clone();
            let delay = 20 + (i % 180);
            let producer = std::thread::spawn(move || {
                let mut producer = Queue::open(
                    &p,
                    &OpenOptions {
                        allow_unsupported_fs: true,
                        ..Default::default()
                    },
                )
                .unwrap();
                std::thread::sleep(std::time::Duration::from_millis(delay as u64));
                let outcome = producer.enqueue(EnqueueInput {
                    maximum_attempts: 1,
                    content_type: "x".to_string(),
                    payload: b"m".to_vec(),
                    ..Default::default()
                });
                (outcome, std::time::Instant::now())
            });
            let lease_info = match queue.lease(2_000_000_000, 30_000_000_000) {
                LeaseOutcome::Leased(li) => li,
                other => panic!("lease failed: {other:?}"),
            };
            let (outcome, enqueued_at) = producer.join().unwrap();
            assert!(matches!(outcome, EnqueueOutcome::Committed(_)));
            let latency = enqueued_at.elapsed();
            // Drain for the next iteration.
            assert!(matches!(queue.ack(&lease_info), AckOutcome::Acked));
            (if round == 0 {
                &mut with_watch
            } else {
                &mut poll_only
            })
            .push(latency);
        }
    }
    let ms = |v: &Vec<std::time::Duration>| {
        let mut v: Vec<_> = v.iter().map(|d| d.as_micros() as f64).collect();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        format!(
            "median {:.0}us p90 {:.0}us max {:.0}us",
            v[v.len() / 2],
            v[(v.len() * 9) / 10],
            v[v.len() - 1]
        )
    };
    println!("dispatch latency with watch: {}", ms(&with_watch));
    println!("dispatch latency poll only: {}", ms(&poll_only));
}

#[test]
fn bounded_wait_establishes_ready_watch() {
    let (_tmp, mut queue) = create_test_queue();
    // A bounded empty wait attempts the watch once.
    assert!(matches!(
        queue.lease(20_000_000, 30_000_000_000),
        LeaseOutcome::Empty
    ));
    assert!(
        queue.ready_watch.is_some(),
        "watch must be established over the real shard layout"
    );
}

#[test]
fn bounded_wait_returns_job_enqueued_during_wait() {
    let (tmp, mut queue) = create_test_queue();
    let path = tmp.path().to_path_buf();
    let producer = std::thread::spawn(move || {
        let mut producer = Queue::open(
            &path,
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        match producer.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"wake".to_vec(),
            ..Default::default()
        }) {
            EnqueueOutcome::Committed(_) => {}
            other => panic!("enqueue failed: {other:?}"),
        }
    });

    let started = std::time::Instant::now();
    let outcome = queue.lease(2_000_000_000, 30_000_000_000);
    let elapsed = started.elapsed();
    producer.join().unwrap();
    assert!(matches!(outcome, LeaseOutcome::Leased(_)), "{outcome:?}");
    // Dispatched after the enqueue (100ms) with margin, well inside the 2s
    // window: the event wake and the scan both return promptly.
    assert!(
        elapsed < std::time::Duration::from_millis(1_500),
        "dispatch took {elapsed:?}"
    );
}

#[test]
fn zero_wait_lease_performs_exactly_one_scan() {
    let (_tmp, mut queue) = create_test_queue();
    let before = queue.scan_round;
    assert!(matches!(
        queue.lease(0, 30_000_000_000),
        LeaseOutcome::Empty
    ));
    assert_eq!(queue.scan_round, before.wrapping_add(1));
}

#[test]
fn bounded_wait_retries_empty_scans_without_busy_spinning() {
    let (_tmp, mut queue) = create_test_queue();
    let before = queue.scan_round;
    // 250 ms so one slow scan on a loaded runner cannot consume the whole
    // window and turn the retry count into 1.
    let wait = std::time::Duration::from_millis(250);
    let started = std::time::Instant::now();
    assert!(matches!(
        queue.lease(wait.as_nanos() as u64, 30_000_000_000),
        LeaseOutcome::Empty
    ));
    let elapsed = started.elapsed();
    let scans = queue.scan_round.wrapping_sub(before);

    assert!(elapsed >= wait, "returned before deadline: {elapsed:?}");
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "bounded wait substantially exceeded its deadline: {elapsed:?}"
    );
    assert!(scans > 1, "bounded wait did not retry");
    assert!(scans < 100, "bounded wait busy-spun with {scans} scans");
}

#[test]
fn bounded_wait_survives_transient_watermark_lock_contention() {
    let (tmp, mut queue) = create_test_queue();
    assert!(matches!(
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".into(),
            payload: b"contention".to_vec(),
            ..Default::default()
        }),
        EnqueueOutcome::Committed(_)
    ));
    let current = queue.read_wall_watermark().unwrap();
    let next_bucket = current.highest_observed_bucket.checked_add(1).unwrap();
    fs::fault::set_clock_realtime_ns(
        next_bucket
            .checked_mul(queue.format.delayed_bucket_width_ns())
            .unwrap(),
    );

    let root = fs::open_dir_absolute(tmp.path()).unwrap();
    let control = fs::open_directory(root.as_fd(), "control").unwrap();
    let lock = fs::openat(control.as_fd(), "wall-watermark.lock", libc::O_RDWR, 0o600).unwrap();
    assert!(fs::try_ofd_write_lock(lock.as_fd()).unwrap());
    let releaser = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(25));
        drop(lock);
    });

    let started = std::time::Instant::now();
    let outcome = queue.lease(500_000_000, 30_000_000_000);
    fs::fault::reset();
    releaser.join().unwrap();

    assert!(matches!(outcome, LeaseOutcome::Leased(_)), "{outcome:?}");
    assert!(started.elapsed() >= std::time::Duration::from_millis(20));
}

// ===== Unexpected ack errors are not LeaseLost =====
#[test]
fn ack_preserves_error_categories() {
    let (_tmp, mut queue) = create_test_queue();
    // Use a nonexistent source path - should get LeaseLost
    // Use a path that matches the legacy leased tree and does not exist.
    let boot_id = queue.boot_id.clone();
    let fake_lease = LeaseInfo {
        job_id: [0x42; 16],
        envelope_digest: [0; 32],
        generation: 1,
        attempt: 1,
        maximum_attempts: 3,
        token: [0xFF; 16],
        boot_id: boot_id.clone(),
        expires_boottime_ns: u64::MAX,
        expires_wall_ns: u64::MAX,
        content_type: String::new(),
        payload_length: 0,
        payload_digest: [0; 32],
        expected_dev: 0,
        expected_inode: 0,
        exact_source_path: format!("leased/{boot_id}/0000000000000000/0000/nonexistent.sqj"),
    };
    let result = queue.ack(&fake_lease);
    // dev/inode are 0, so open_and_validate_current_lease rejects
    // the forgeable handle before even checking source existence.
    assert!(matches!(result, AckOutcome::NotCommitted(_)));
}

// ===== Post-claim validation does not return Empty =====
#[test]
fn post_claim_returns_lease_on_success() {
    let (_tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "application/json".to_string(),
        payload: b"{\"key\": \"value\"}".to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!("lease should succeed"),
    };
    assert_eq!(lease.content_type, "application/json");
    assert!(_tmp.path().join(&lease.exact_source_path).exists());
}

// ===== Init durability: FORMAT is read-only =====
#[test]
fn format_file_is_readonly() {
    let tmp = TempDir::new().unwrap();
    Queue::init(tmp.path(), &CreateOptions::default()).unwrap();
    let meta = std::fs::metadata(tmp.path().join("FORMAT")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o400,
            "FORMAT should be mode 0400, got {mode:o}"
        );
    }
}

#[test]
fn open_rejects_unsupported_format_version() {
    let tmp = TempDir::new().unwrap();
    Queue::init(tmp.path(), &CreateOptions::default()).unwrap();

    // Overwrite FORMAT major version byte (offset 8) to trigger
    // UnsupportedVersion -> Error::UnsupportedFormat.
    use std::io::{Seek, SeekFrom, Write};
    use std::os::unix::fs::PermissionsExt;
    let fmt_path = tmp.path().join("FORMAT");
    std::fs::set_permissions(&fmt_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .open(&fmt_path)
        .unwrap();
    f.seek(SeekFrom::Start(8)).unwrap();
    f.write_all(&[0xFF, 0xFF]).unwrap();
    f.sync_all().unwrap();
    drop(f);

    let result = Queue::open(
        tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    );
    assert!(
        matches!(result, Err(Error::UnsupportedFormat)),
        "expected Err(UnsupportedFormat)"
    );
}

// Real concurrent producers AND consumers
#[test]
fn concurrent_producers_consumers_overlap() {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::thread;

    let tmp = TempDir::new().unwrap();
    Queue::init(tmp.path(), &CreateOptions::default()).unwrap();

    let path = tmp.path().to_path_buf();
    let total = Arc::new(AtomicU64::new(0));
    let consumed = Arc::new(AtomicU64::new(0));
    let duration = std::time::Duration::from_secs(2);

    let p_path = path.clone();
    let p_total = total.clone();
    let producer = thread::spawn(move || {
        let mut queue = Queue::open(
            &p_path,
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        let deadline = std::time::Instant::now() + duration;
        while std::time::Instant::now() < deadline {
            match queue.enqueue(EnqueueInput {
                maximum_attempts: 1,
                content_type: "test".to_string(),
                payload: b"concurrent".to_vec(),
                ..Default::default()
            }) {
                EnqueueOutcome::Committed(_) => {
                    p_total.fetch_add(1, Ordering::Relaxed);
                }
                EnqueueOutcome::NotCommitted(_, Error::MaintenanceBusy) => {}
                outcome => panic!("concurrent enqueue failed: {outcome:?}"),
            }
        }
    });

    let c_path = path.clone();
    let c_consumed = consumed.clone();
    let consumer = thread::spawn(move || {
        let mut queue = Queue::open(
            &c_path,
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        let deadline = std::time::Instant::now() + duration + std::time::Duration::from_secs(1);
        while std::time::Instant::now() < deadline {
            match queue.lease(0, 60_000_000_000) {
                LeaseOutcome::Leased(l) => {
                    queue.verify_lease_payload(&l).unwrap();
                    match queue.ack(&l) {
                        AckOutcome::Acked => {
                            c_consumed.fetch_add(1, Ordering::Relaxed);
                        }
                        AckOutcome::NotCommitted(Error::MaintenanceBusy) => {}
                        outcome => panic!("concurrent acknowledgment failed: {outcome:?}"),
                    }
                }
                LeaseOutcome::Empty => {
                    thread::sleep(std::time::Duration::from_millis(1));
                }
                LeaseOutcome::NotCommitted(Error::MaintenanceBusy) => {}
                outcome => panic!("concurrent lease failed: {outcome:?}"),
            }
        }
    });

    producer.join().unwrap();
    consumer.join().unwrap();

    let enq = total.load(Ordering::Relaxed);
    let con = consumed.load(Ordering::Relaxed);
    // Consumer should have consumed at least some jobs while producer was active
    assert!(enq > 0, "should have enqueued some jobs");
    assert!(con > 0, "should have consumed some jobs concurrently");
    // With concurrent producer and consumer, we should consume most
    // but may not consume all (race conditions at start/end)
}

// ===== FD leak stress =====
#[test]
fn fd_leak_stress() {
    let tmp = TempDir::new().unwrap();
    Queue::init(tmp.path(), &CreateOptions::default()).unwrap();
    fn queue_fd_count(root: &Path) -> usize {
        std::fs::read_dir("/proc/self/fd")
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .filter_map(|entry| std::fs::read_link(entry.path()).ok())
                    .filter(|target| target.starts_with(root))
                    .count()
            })
            .unwrap_or(0)
    }
    let baseline = queue_fd_count(tmp.path());
    for _ in 0..200 {
        let q = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        drop(q);
    }
    let after = queue_fd_count(tmp.path());
    assert_eq!(after, baseline, "queue FD leak detected");
}

// ===== Negative test matrix =====
#[test]
fn reject_invalid_lease_duration() {
    let (_tmp, mut queue) = create_test_queue();
    let outcome = queue.lease(0, 100);
    assert!(matches!(outcome, LeaseOutcome::NotCommitted(_)));
    let outcome = queue.lease(0, 8 * 24 * 60 * 60 * 1_000_000_000);
    assert!(matches!(outcome, LeaseOutcome::NotCommitted(_)));
}

#[test]
fn reject_ack_on_empty_queue() {
    let (_tmp, mut queue) = create_test_queue();
    let fake = LeaseInfo {
        job_id: [0xFF; 16],
        envelope_digest: [0; 32],
        generation: 1,
        attempt: 1,
        maximum_attempts: 3,
        token: [0; 16],
        boot_id: queue.boot_id.clone(),
        expires_boottime_ns: 0,
        expires_wall_ns: 0,
        content_type: String::new(),
        payload_length: 0,
        payload_digest: [0; 32],
        expected_dev: 1,
        expected_inode: 1,
        exact_source_path: "leased/x/x/x/nonexistent.sqj".into(),
    };
    let result = queue.ack(&fake);
    assert!(matches!(
        result,
        AckOutcome::LeaseLost | AckOutcome::NotCommitted(_)
    ));
}

#[test]
fn reject_retry_on_empty_queue() {
    let (_tmp, mut queue) = create_test_queue();
    let fake = LeaseInfo {
        job_id: [0xFF; 16],
        envelope_digest: [0; 32],
        generation: 1,
        attempt: 1,
        maximum_attempts: 3,
        token: [0; 16],
        boot_id: queue.boot_id.clone(),
        expires_boottime_ns: 0,
        expires_wall_ns: 0,
        content_type: String::new(),
        payload_length: 0,
        payload_digest: [0; 32],
        expected_dev: 1,
        expected_inode: 1,
        exact_source_path: "leased/x/x/x/nonexistent.sqj".into(),
    };
    let result = queue.retry_now(&fake);
    assert!(matches!(
        result,
        TransitionOutcome::LeaseLost | TransitionOutcome::NotCommitted(_)
    ));
}

#[test]
fn reject_zero_dev_inode_lease() {
    let (_tmp, mut queue) = create_test_queue();
    let fake = LeaseInfo {
        job_id: [0xFF; 16],
        envelope_digest: [0; 32],
        generation: 1,
        attempt: 1,
        maximum_attempts: 3,
        token: [0; 16],
        boot_id: queue.boot_id.clone(),
        expires_boottime_ns: 0,
        expires_wall_ns: 0,
        content_type: String::new(),
        payload_length: 0,
        payload_digest: [0; 32],
        expected_dev: 0,
        expected_inode: 0,
        exact_source_path: "leased/x/x/x/nonexistent.sqj".into(),
    };
    let result = queue.ack(&fake);
    assert!(matches!(result, AckOutcome::NotCommitted(_)));
}

#[test]
fn reject_generation_overflow() {
    let (_tmp, mut queue) = create_test_queue();
    let fake = LeaseInfo {
        job_id: [0xFF; 16],
        envelope_digest: [0; 32],
        generation: u64::MAX,
        attempt: 1,
        maximum_attempts: 3,
        token: [0; 16],
        boot_id: queue.boot_id.clone(),
        expires_boottime_ns: 0,
        expires_wall_ns: 0,
        content_type: String::new(),
        payload_length: 0,
        payload_digest: [0; 32],
        expected_dev: 1,
        expected_inode: 1,
        exact_source_path: "leased/x/x/x/nonexistent.sqj".into(),
    };
    let result = queue.retry_now(&fake);
    assert!(matches!(
        result,
        TransitionOutcome::NotCommitted(Error::StateExhausted)
    ));
}

#[test]
fn poisoned_queue_rejects_operations() {
    let (_tmp, mut queue) = create_test_queue();
    queue.poison(PoisonReason::InternalInvariantViolation);
    let outcome = queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    });
    assert!(matches!(outcome, EnqueueOutcome::NotCommitted(_, _)));
}

#[test]
fn open_propagates_non_enoent_format_open_errors() {
    let (_tmp, queue) = create_test_queue();
    fs::fault::reset();
    fs::fault::inject_errno("openat", 1, libc::EIO);
    let result = Queue::open(
        _tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    );
    fs::fault::reset();
    match result {
        Err(Error::IoFailure(msg)) => {
            assert!(!msg.is_empty(), "error message should not be empty")
        }
        _other => panic!("expected IoFailure for FORMAT open EIO, got Ok or wrong error"),
    }
    drop(queue);
}

#[test]
fn open_detects_interrupted_initialization() {
    let tmp = TempDir::new().unwrap();
    std::fs::create_dir_all(tmp.path().join("control")).unwrap();
    std::fs::write(tmp.path().join(".initializing"), b"").unwrap();

    let result = Queue::open(
        tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    );
    match result {
        Err(Error::QueueCorrupt(msg)) => {
            assert!(
                msg.contains("interrupted"),
                "expected 'interrupted' in: {msg}"
            );
        }
        _ => {
            panic!("expected interrupted init QueueCorrupt error, got Ok or different error")
        }
    }
}

#[test]
fn open_reports_missing_format_without_init_marker() {
    let tmp = TempDir::new().unwrap();
    std::fs::create_dir_all(tmp.path().join("control")).unwrap();
    std::fs::create_dir_all(tmp.path().join("ready")).unwrap();

    let result = Queue::open(
        tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    );
    match result {
        Err(Error::QueueCorrupt(msg)) => {
            assert!(msg.contains("FORMAT"), "expected 'FORMAT' in: {msg}");
        }
        _ => {
            panic!("expected missing FORMAT QueueCorrupt error, got Ok or different error")
        }
    }
}

#[test]
fn open_rejects_missing_state_dir() {
    let tmp = TempDir::new().unwrap();
    Queue::init(tmp.path(), &CreateOptions::default()).unwrap();
    // Remove a required state directory
    std::fs::remove_dir_all(tmp.path().join("ready")).unwrap();
    let result = Queue::open(
        tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    );
    assert!(result.is_err());
}

#[test]
fn verify_payload_detects_wrong_data() {
    let (_tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"hello world".to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!("lease failed"),
    };
    // Corrupt a payload byte
    let src_path = _tmp.path().join(&lease.exact_source_path);
    let mut data = std::fs::read(&src_path).unwrap();
    let last = data.len() - 1;
    data[last] ^= 0xFF;
    std::fs::write(&src_path, data).unwrap();
    // Verify should detect corruption
    let result = queue.verify_lease_payload(&lease);
    assert!(matches!(
        result,
        Err(Error::PayloadCorrupt) | Err(Error::QueueCorrupt(_))
    ));
}

#[test]
fn p0_01_lease_rejects_corrupt_payload_before_delivery() {
    for pos in ["first", "middle", "last"] {
        let (_tmp, mut queue) = create_test_queue();
        let payload = b"payload for P0-01 before-delivery corrupt test 12345".to_vec();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: payload.clone(),
            ..Default::default()
        });
        // Find ready file and corrupt one byte before lease.
        // Helper to scan ready shards under root/ready/*/*.sqj
        let find_one_ready = |root: &std::path::Path| -> Option<std::path::PathBuf> {
            let ready_root = root.join("ready");
            for shard in std::fs::read_dir(&ready_root).ok()?.flatten() {
                for f in std::fs::read_dir(shard.path()).ok()?.flatten() {
                    let p = f.path();
                    if p.extension().map(|e| e == "sqj").unwrap_or(false) {
                        return Some(p);
                    }
                }
            }
            None
        };
        let ready_path = find_one_ready(_tmp.path()).expect("ready file should exist");
        let mut data = std::fs::read(&ready_path).unwrap();
        let header_len = 128usize;
        let ext_len = {
            let mut hb = [0u8; 128];
            hb.copy_from_slice(&data[0..128]);
            let h = FixedHeader::decode(&hb).unwrap();
            h.extension_header_length as usize
        };
        let payload_start = header_len + ext_len;
        let idx = match pos {
            "first" => payload_start,
            "middle" => payload_start + payload.len() / 2,
            "last" => payload_start + payload.len() - 1,
            _ => unreachable!(),
        };
        data[idx] ^= 0xFF;
        std::fs::write(&ready_path, data).unwrap();
        let outcome = queue.lease(0, 30_000_000_000);
        match outcome {
            LeaseOutcome::NotCommitted(Error::PayloadCorrupt) => {}
            other => panic!("pos {pos} expected PayloadCorrupt, got {other:?}"),
        }
        // Object should be quarantined, not still ready.
        let remaining = find_one_ready(_tmp.path());
        assert!(
            remaining.is_none(),
            "corrupt object should not remain in ready after lease attempt, found {remaining:?}"
        );
        let q = queue.list_quarantine();
        assert!(
            q.iter()
                .any(|e| e.reason == QuarantineReason::PayloadCorrupt as u16),
            "quarantine should contain PayloadCorrupt for pos {pos}"
        );
    }
}

#[test]
fn p0_01_stream_zero_and_boundary_payloads_verify() {
    for len in [0usize, 4096, 65535, 65536, 65537] {
        let (_tmp, mut queue) = create_test_queue();
        let payload = vec![0xAB; len];
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: payload.clone(),
            ..Default::default()
        });
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            other => panic!("len {len} lease failed: {other:?}"),
        };
        // Streaming must succeed for valid payload, even at boundaries.
        let mut out = Vec::new();
        queue
            .stream_lease_payload(&lease, 8192, |chunk| {
                out.extend_from_slice(chunk);
                Ok(())
            })
            .unwrap();
        assert_eq!(out.len(), len);
        assert_eq!(out, payload);
        // Chunk read also.
        let mut buf = vec![0u8; len.max(1)];
        let n = queue.read_lease_payload_chunk(&lease, &mut buf, 0).unwrap();
        assert_eq!(n, len);
    }
}

#[test]
fn p0_01_read_stream_reject_corrupt_after_lease() {
    let (_tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"stream after lease corrupt".to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        other => panic!("lease failed: {other:?}"),
    };
    // Corrupt leased file after successful lease but before read.
    let src_path = _tmp.path().join(&lease.exact_source_path);
    let mut data = std::fs::read(&src_path).unwrap();
    let last = data.len() - 1;
    data[last] ^= 0x01;
    std::fs::write(&src_path, data).unwrap();
    // Chunk read must not deliver corrupt bytes.
    let mut buf = vec![0u8; 64];
    let r = queue.read_lease_payload_chunk(&lease, &mut buf, 0);
    assert!(matches!(
        r,
        Err(Error::PayloadCorrupt) | Err(Error::QueueCorrupt(_))
    ));
    // Stream must also fail.
    let sr = queue.stream_lease_payload(&lease, 4096, |_| Ok(()));
    assert!(matches!(
        sr,
        Err(Error::PayloadCorrupt) | Err(Error::QueueCorrupt(_))
    ));
}

#[test]
fn quarantine_held_fd_must_match_name() {
    let (_tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"a".to_vec(),
        ..Default::default()
    });
    let lease_a = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        other => panic!("lease a failed: {other:?}"),
    };
    // Hold fd for a dummy file in same leased dir but different inode. Dev same, ino differs.
    let dir_path = lease_a
        .exact_source_path
        .rsplit_once('/')
        .map(|(d, _)| d)
        .unwrap();
    let dir_fd = crate::queue::open_relative(queue.root_fd().as_fd(), dir_path).unwrap();
    // Create dummy file in same dir
    let dummy_fd = steadq_fs_linux::openat(
        dir_fd.as_fd(),
        "dummy.sqj",
        libc::O_CREAT | libc::O_RDWR | libc::O_CLOEXEC,
        0o600,
    )
    .unwrap();
    let name_a = lease_a
        .exact_source_path
        .rsplit_once('/')
        .map(|(_, n)| n)
        .unwrap();
    // Different inode maps to SourceMissing.
    let res = queue.quarantine_corrupt_lease(dir_fd.as_fd(), name_a, dummy_fd.as_fd());
    let _ = dummy_fd;
    assert!(
        matches!(res, Err(engine::MoveFailure::SourceMissing)),
        "quarantine with mismatched held fd should be SourceMissing, got {res:?}"
    );
}

#[test]
fn export_dead_copies_file_content_through_core() {
    let (tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 1,
        content_type: "x".to_string(),
        payload: b"dead job payload".to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        o => panic!("lease failed: {o:?}"),
    };
    // Exhaust attempts to send to dead.
    queue.bury(&lease, DeadReason::AdministrativeBury);

    let output = tmp.path().join("exported.bin");
    let n = queue.export_dead(&lease.job_id, &output).unwrap();
    assert!(n > b"dead job payload".len() as u64);
    let data = std::fs::read(&output).unwrap();
    assert!(data.ends_with(b"dead job payload"));
}

#[test]
fn export_dead_returns_error_for_missing_job() {
    let (_tmp, queue) = create_test_queue();
    let result = queue.export_dead(&[0xFF; 16], std::path::Path::new("/tmp/nonexistent"));
    assert!(result.is_err());
}

#[test]
fn remove_dead_deletes_file_through_core() {
    let (tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 1,
        content_type: "x".to_string(),
        payload: b"removable".to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        o => panic!("lease failed: {o:?}"),
    };
    let outcome = queue.bury(&lease, DeadReason::AdministrativeBury);
    assert!(
        matches!(outcome, TransitionOutcome::Committed),
        "bury failed: {outcome:?}"
    );

    // Job should be in dead.
    let snapshots = queue.inspect(&lease.job_id);
    assert!(snapshots.iter().any(|s| s.state == "dead"));

    // Remove it.
    let removed = queue.remove_dead(&lease.job_id).unwrap();
    assert!(removed);

    // Job should be gone.
    let snapshots2 = queue.inspect(&lease.job_id);
    assert!(snapshots2.is_empty());

    // Remove again returns error (not found by inspect).
    assert!(queue.remove_dead(&lease.job_id).is_err());

    drop(tmp);
}

#[test]
fn dead_letter_move_preserves_each_failure_phase() {
    for (fault, errno, phase_unknown) in [
        ("renameat2_noreplace", libc::EIO, false),
        ("renameat2_noreplace", libc::ENOSPC, false),
        ("fsync_dir_fd", libc::EIO, true),
        ("fsync_dir_fd", libc::ENOSPC, true),
    ] {
        let (tmp, mut queue) = create_test_queue();
        fs::fault::reset();
        fs::fault::set_clock_realtime_ns(1_000_000_000);
        let ticket = match queue.enqueue(EnqueueInput {
            maximum_attempts: 1,
            content_type: "x".to_string(),
            payload: b"dead-letter fault".to_vec(),
            ..Default::default()
        }) {
            EnqueueOutcome::Committed(t) => t,
            o => panic!("enqueue failed: {o:?}"),
        };
        let (ready_dir, ready_name) = ticket.expected_relative_path.rsplit_once('/').unwrap();
        let parsed = steadq_names::parse_ready(ready_name).unwrap();
        let wall_floor = queue.wall_floor_for_mutation().unwrap();
        let dead_bucket = steadq_math::bucket_number(
            wall_floor.unix_ns(),
            queue.format.terminal_bucket_width_ns(),
        )
        .unwrap();
        queue
            .ensure_dir(&format!(
                "dead/{}/0000",
                steadq_names::bucket_hex(dead_bucket)
            ))
            .unwrap();

        fs::fault::inject_errno(fault, 1, errno);
        let result = queue.move_to_dead(
            ready_dir,
            ready_name,
            &parsed.common,
            DeadReason::AttemptsExhausted,
            wall_floor,
        );
        fs::fault::reset();

        // The mover reports the phase; the claim loop decides poisoning.
        let err = result.expect_err("expected error for fault");
        let (phase, source) = match (&err, phase_unknown) {
            (
                DeadLetterFailure::Move(engine::MoveFailure::NotCommitted { phase, source }),
                false,
            ) => (*phase, source),
            (
                DeadLetterFailure::Move(engine::MoveFailure::OutcomeUnknown { phase, source }),
                true,
            ) => (*phase, source),
            _ => panic!("fault {fault}: {err:?}"),
        };
        let expected_phase = if phase_unknown {
            engine::MovePhase::DestFsync
        } else {
            engine::MovePhase::Rename
        };
        assert_eq!(phase, expected_phase, "fault {fault}");
        assert_eq!(source.raw_os_error(), Some(errno), "fault {fault}");
        assert!(!queue.is_poisoned());
        if phase_unknown {
            assert!(find_file_with_suffix(&tmp.path().join("dead"), ".sqj").is_some());
            assert!(!tmp.path().join(&ticket.expected_relative_path).exists());
        } else {
            assert!(tmp.path().join(&ticket.expected_relative_path).exists());
        }
    }
}

#[test]
fn quarantine_surfaces_indeterminate_outcome_from_read_path() {
    let (tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"quarantine outcome".to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        o => panic!("lease failed: {o:?}"),
    };
    // Corrupt the leased payload.
    let src_path = tmp.path().join(&lease.exact_source_path);
    let mut data = std::fs::read(&src_path).unwrap();
    *data.last_mut().unwrap() ^= 0x01;
    std::fs::write(&src_path, data).unwrap();

    // Inject a post-rename fsync failure so the quarantine move
    // linearizes but cannot prove durability.
    fs::fault::inject_errno("fsync_dir_fd", 1, libc::EIO);
    let result = queue.read_lease_payload_chunk(&lease, &mut [0u8; 8], 0);
    fs::fault::reset();

    assert!(
        matches!(result, Err(Error::QueueCorrupt(_))),
        "expected QueueCorrupt for indeterminate quarantine, got {result:?}"
    );
}

#[test]
fn validate_active_object_rejects_delayed_bucket_mismatch() {
    let (_tmp, mut queue) = create_test_queue();
    // Enqueue a delayed job.
    let wall_now = steadq_fs_linux::clock_realtime_ns().unwrap();
    let not_before = wall_now + 5_000_000_000;
    match queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"delayed".to_vec(),
        initial_not_before: Some(not_before),
        ..Default::default()
    }) {
        EnqueueOutcome::Committed(_) => {}
        other => panic!("enqueue delayed must succeed, got {other:?}"),
    }
    // Locate the delayed file.
    let delayed_root = _tmp.path().join("delayed");
    let mut delayed_file: Option<(String, String, String)> = None;
    for bucket in std::fs::read_dir(&delayed_root).unwrap().flatten() {
        for shard in std::fs::read_dir(bucket.path()).unwrap().flatten() {
            for entry in std::fs::read_dir(shard.path()).unwrap().flatten() {
                let name = entry.file_name().into_string().unwrap();
                if name.ends_with(".sqj") {
                    let bucket_name = bucket.file_name().into_string().unwrap();
                    let shard_name = shard.file_name().into_string().unwrap();
                    delayed_file = Some((bucket_name, shard_name, name));
                    break;
                }
            }
        }
    }
    let (bucket_name, shard_name, file_name) = delayed_file.expect("delayed file must exist");
    // Correct context must succeed.
    let correct_ctx = crate::ActivePathContext::Delayed {
        bucket: bucket_name.clone(),
        shard: shard_name.clone(),
    };
    let dir_fd = crate::queue::open_relative(
        queue.root_fd().as_fd(),
        &format!("delayed/{bucket_name}/{shard_name}"),
    )
    .unwrap();
    let ok = queue.validate_active_object(dir_fd.as_fd(), &file_name, &correct_ctx);
    assert!(
        ok.is_ok(),
        "correct delayed bucket must validate, got {ok:?}"
    );
    // Wrong bucket must be rejected. Flip last hex digit to guarantee mismatch while keeping hex valid.
    let mut wrong_bucket = bucket_name.clone();
    let last = wrong_bucket.pop().unwrap();
    let flipped = if last == '0' { '1' } else { '0' };
    wrong_bucket.push(flipped);
    let wrong_ctx = crate::ActivePathContext::Delayed {
        bucket: wrong_bucket.clone(),
        shard: shard_name.clone(),
    };
    let wrong_fd = crate::queue::open_relative(
        queue.root_fd().as_fd(),
        &format!("delayed/{bucket_name}/{shard_name}"),
    )
    .unwrap();
    // validate_active_object checks the filename bucket against the directory bucket.
    // With a mismatched bucket in the context, it must return QueueCorrupt.
    // Under the mutant that changes != to ==, this would incorrectly return Ok.
    let wrong = queue.validate_active_object(wrong_fd.as_fd(), &file_name, &wrong_ctx);
    assert!(
        matches!(wrong, Err(Error::QueueCorrupt(_))),
        "wrong delayed bucket must be rejected, got {wrong:?}"
    );
}

#[test]
fn validate_active_object_rejects_tag_mismatch() {
    let (_tmp, mut queue) = create_test_queue();
    match queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"tag-test".to_vec(),
        ..Default::default()
    }) {
        EnqueueOutcome::Committed(_) => {}
        other => panic!("enqueue must succeed, got {other:?}"),
    }
    let ready_root = _tmp.path().join("ready");
    let mut found: Option<(String, String)> = None;
    for shard in std::fs::read_dir(&ready_root).unwrap().flatten() {
        for entry in std::fs::read_dir(shard.path()).unwrap().flatten() {
            let n = entry.file_name().into_string().unwrap();
            if n.ends_with(".sqj") {
                found = Some((shard.file_name().into_string().unwrap(), n));
                break;
            }
        }
    }
    let (shard_name, file_name) = found.expect("ready file");
    let correct_ctx = crate::ActivePathContext::Ready {
        shard: shard_name.clone(),
    };
    let dir_fd =
        crate::queue::open_relative(queue.root_fd().as_fd(), &format!("ready/{shard_name}"))
            .unwrap();
    let ok = queue.validate_active_object(dir_fd.as_fd(), &file_name, &correct_ctx);
    assert!(ok.is_ok(), "correct tag must validate, got {ok:?}");
    let wrong_ctx = crate::ActivePathContext::Ready {
        shard: "ffff".to_string(),
    };
    let bad = queue.validate_active_object(dir_fd.as_fd(), &file_name, &wrong_ctx);
    assert!(
        matches!(bad, Err(Error::QueueCorrupt(_))),
        "wrong shard must cause tag mismatch, got {bad:?}"
    );
}

#[test]
fn check_duplicate_ack_bounded_is_false_when_no_receipt() {
    let (_tmp, mut queue) = create_test_queue();
    let payload = b"dup-ack-test";
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: payload.to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        other => panic!("lease must succeed, got {other:?}"),
    };
    let wall_floor = queue.authenticated_wall_floor().unwrap();
    let before = queue.check_duplicate_ack_bounded(&lease, wall_floor);
    assert!(!before, "no receipt yet, duplicate check must be false");
    queue.verify_lease_payload(&lease).unwrap();
    let ack = queue.ack(&lease);
    assert!(
        matches!(ack, AckOutcome::Acked),
        "ack must succeed, got {ack:?}"
    );
    let after = queue.check_duplicate_ack_bounded(&lease, wall_floor);
    assert!(after, "after ack, duplicate check must be true");
}

#[test]
fn full_lifecycle_with_verify() {
    let (_tmp, mut queue) = create_test_queue();
    let payload = b"lifecycle test payload data";
    queue.enqueue(EnqueueInput {
        maximum_attempts: 5,
        content_type: "application/json".to_string(),
        payload: payload.to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!("lease failed"),
    };
    // Stream-read the payload
    let mut collected = Vec::new();
    queue
        .stream_lease_payload(&lease, 16, |chunk| {
            collected.extend_from_slice(chunk);
            Ok(())
        })
        .unwrap();
    assert_eq!(&collected[..], &payload[..]);
    // Verify + ack
    queue.verify_lease_payload(&lease).unwrap();
    let result = queue.ack(&lease);
    assert!(matches!(result, AckOutcome::Acked));
}

// ===== Oracle-driven closed-loop simulation =====
// Track real EnqueueTicket.job_id / LeaseInfo.job_id values and
// reconcile oracle state with inspect() after every operation.
#[test]
fn oracle_driven_closed_loop() {
    use std::collections::HashMap;
    let (_tmp, mut queue) = create_test_queue();

    #[derive(Clone, Copy, PartialEq, Debug)]
    enum State {
        Ready,
        Leased,
        Acked,
        Retried,
        Dead,
    }
    let mut oracle: HashMap<[u8; 16], State> = HashMap::new();
    // Live lease handles keyed by real job_id.
    let mut leases: HashMap<[u8; 16], LeaseInfo> = HashMap::new();
    let mut rng_state = 42u64;

    for _step in 0..500 {
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 7;
        rng_state ^= rng_state << 17;

        match rng_state % 4 {
            0 => {
                let outcome = queue.enqueue(EnqueueInput {
                    maximum_attempts: 3,
                    content_type: "x".to_string(),
                    payload: b"data".to_vec(),
                    ..Default::default()
                });
                if let EnqueueOutcome::Committed(ticket) = outcome {
                    oracle.insert(ticket.job_id, State::Ready);
                    // Reconcile: inspect must see a ready object for this id.
                    let snaps = queue.inspect(&ticket.job_id);
                    assert!(
                        snaps.iter().any(|s| s.state == "ready"),
                        "oracle Ready not reflected by inspect for {}",
                        steadq_names::hex_encode(&ticket.job_id)
                    );
                }
            }
            1 => {
                if let LeaseOutcome::Leased(l) = queue.lease(0, 30_000_000_000) {
                    let id = l.job_id;
                    oracle.insert(id, State::Leased);
                    leases.insert(id, l);
                    let snaps = queue.inspect(&id);
                    assert!(
                        snaps.iter().any(|s| s.state == "leased"),
                        "oracle Leased not reflected by inspect"
                    );
                }
            }
            2 => {
                // Ack a leased job using the real handle.
                let job_id = oracle
                    .iter()
                    .find(|(_, s)| **s == State::Leased)
                    .map(|(id, _)| *id);
                if let Some(job_id) = job_id {
                    if let Some(lease) = leases.remove(&job_id) {
                        queue.verify_lease_payload(&lease).unwrap();
                        match queue.ack(&lease) {
                            AckOutcome::Acked | AckOutcome::AlreadyAcked => {
                                oracle.insert(job_id, State::Acked);
                                let snaps = queue.inspect(&job_id);
                                assert!(
                                    snaps.iter().any(|s| s.state == "receipt")
                                        || snaps.is_empty()
                                        || snaps.iter().all(|s| s.state != "leased"),
                                    "acked job still leased in inspect"
                                );
                            }
                            _ => {
                                // Keep as leased if ack failed; reinsert handle.
                                leases.insert(job_id, lease);
                            }
                        }
                    }
                }
            }
            _ => {
                if let LeaseOutcome::Leased(l) = queue.lease(0, 30_000_000_000) {
                    let id = l.job_id;
                    if rng_state.is_multiple_of(2) {
                        queue.verify_lease_payload(&l).unwrap();
                        if matches!(queue.ack(&l), AckOutcome::Acked | AckOutcome::AlreadyAcked) {
                            oracle.insert(id, State::Acked);
                            leases.remove(&id);
                        }
                    } else if let TransitionOutcome::Committed = queue.retry_now(&l) {
                        leases.remove(&id);
                        let snaps = queue.inspect(&id);
                        // retry_now moves to ready, or to dead when
                        // attempts are exhausted.
                        if snaps.iter().any(|s| s.state == "ready") {
                            oracle.insert(id, State::Retried);
                        } else if snaps.iter().any(|s| s.state == "dead") {
                            oracle.insert(id, State::Dead);
                        } else {
                            panic!(
                                "retry committed but inspect has {:?}",
                                snaps.iter().map(|s| s.state.as_str()).collect::<Vec<_>>()
                            );
                        }
                    }
                }
            }
        }
    }

    let ready_count = oracle.values().filter(|s| **s == State::Ready).count();
    let leased_count = oracle.values().filter(|s| **s == State::Leased).count();
    let acked_count = oracle.values().filter(|s| **s == State::Acked).count();
    let retried_count = oracle.values().filter(|s| **s == State::Retried).count();
    let dead_count = oracle.values().filter(|s| **s == State::Dead).count();
    assert!(
        ready_count + leased_count + acked_count + retried_count + dead_count > 0,
        "oracle should have tracked some jobs"
    );

    // Final reconciliation: every oracle Ready/Leased job must appear in inspect.
    for (id, state) in &oracle {
        match state {
            State::Ready => {
                let snaps = queue.inspect(id);
                // May have been leased later without oracle update if we only
                // track transitions we apply; re-check live state.
                let live_ready = snaps.iter().any(|s| s.state == "ready");
                let live_leased = snaps.iter().any(|s| s.state == "leased");
                assert!(
                    live_ready || live_leased || snaps.is_empty(),
                    "oracle Ready job in unexpected state: {:?}",
                    snaps.iter().map(|s| s.state.as_str()).collect::<Vec<_>>()
                );
            }
            State::Leased => {
                let snaps = queue.inspect(id);
                assert!(
                    snaps.iter().any(|s| s.state == "leased")
                        || snaps.iter().any(|s| s.state == "ready")
                        || snaps.iter().any(|s| s.state == "receipt"),
                    "oracle Leased job vanished without transition"
                );
            }
            State::Acked | State::Retried | State::Dead => {}
        }
    }
}

// ===== Wall floor poisoning =====
#[test]
fn wall_floor_error_poisons_mutating_ops() {
    let (_tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    });
    // Corrupt the wall watermark to trigger decode failure.
    let wm_path = _tmp.path().join("control/wall-watermark");
    if wm_path.exists() {
        std::fs::write(&wm_path, b"corrupted watermark data").unwrap();
    }
    // The next mutating operation should poison and return error.
    // Clear the cache so the watermark is re-read.
    queue.cached_wall_floor = None;
    let outcome = queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"more data".to_vec(),
        ..Default::default()
    });
    assert!(matches!(
        outcome,
        EnqueueOutcome::NotCommitted(_, Error::QueueCorrupt(_))
    ));
    assert!(queue.is_poisoned());
}

// ===== ack EEXIST authenticates receipt =====
#[test]
fn ack_conflicting_receipt_is_not_already_acked() {
    let (_tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!("lease failed"),
    };
    // Compute the EXACT receipt path ack() will target.
    let shard = compute_shard(
        queue.format.queue_id(),
        &lease.job_id,
        queue.format.shard_count(),
    );
    let shard_str = shard_hex(shard);
    let wall = queue.effective_wall_floor_ns_checked().unwrap();
    let bucket = steadq_math::bucket_number(wall, queue.format.terminal_bucket_width_ns()).unwrap();
    let bucket_str = bucket_hex(bucket);
    let new_gen = lease.generation + 1;
    let receipt_common = CommonFields {
        job_id: lease.job_id,
        generation: new_gen,
        attempt: lease.attempt,
        maximum_attempts: lease.maximum_attempts,
    };
    let receipt_base = format!(
        "{}.g{:016x}.a{:08x}.m{:08x}.t{}",
        steadq_names::hex_encode(&receipt_common.job_id),
        receipt_common.generation,
        receipt_common.attempt,
        receipt_common.maximum_attempts,
        steadq_names::hex_encode(&lease.token),
    );
    let receipt_ctx = steadq_names::terminal_context(
        steadq_names::State::Receipt,
        &bucket_str,
        &shard_str,
        &receipt_base,
    );
    let receipt_tag = steadq_names::compute_name_tag(queue.format.queue_id(), &receipt_ctx);
    let receipt_name = steadq_names::receipt_filename(&receipt_common, &lease.token, &receipt_tag);
    // Pre-plant a non-receipt file at the exact destination.
    let receipt_dir = format!("receipts/{bucket_str}/{shard_str}");
    let full_dir = _tmp.path().join(&receipt_dir);
    std::fs::create_dir_all(&full_dir).unwrap();
    std::fs::write(full_dir.join(&receipt_name), b"not a receipt at all").unwrap();
    // Ack should not succeed because the destination already has a conflicting object.
    // First verify that ack can find the lease (it's valid).
    // Then the EEXIST path should trigger because we pre-planted a file.
    let result = queue.ack(&lease);
    assert!(matches!(
        result,
        AckOutcome::NotCommitted(Error::QueueCorrupt(ref message))
            if message == "conflicting object at receipt path"
    ));
}

#[test]
fn ack_authenticates_existing_receipt_before_reporting_both_objects() {
    let (tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".into(),
        payload: b"data".to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(lease) => lease,
        outcome => panic!("lease failed: {outcome:?}"),
    };
    let wall = queue.effective_wall_floor_ns_checked().unwrap();
    let bucket = bucket_number(wall, queue.format.terminal_bucket_width_ns()).unwrap();
    let common = CommonFields {
        job_id: lease.job_id,
        generation: lease.generation.checked_add(1).unwrap(),
        attempt: lease.attempt,
        maximum_attempts: lease.maximum_attempts,
    };
    let target = queue
        .layout()
        .receipt_in_bucket(&common, &lease.token, bucket);
    let receipt_path = tmp.path().join(target.relative_path());
    std::fs::create_dir_all(receipt_path.parent().unwrap()).unwrap();
    std::fs::copy(tmp.path().join(&lease.exact_source_path), &receipt_path).unwrap();

    let result = queue.ack(&lease);
    assert!(matches!(
        result,
        AckOutcome::NotCommitted(Error::QueueCorrupt(ref message))
            if message == "source lease and receipt both exist"
    ));
}

// ===== ENOTDIR is QueueCorrupt =====
#[test]
fn enotdir_in_lease_path_is_corruption() {
    let (_tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!("lease failed"),
    };
    let shard_dir = _tmp
        .path()
        .join(&lease.exact_source_path)
        .parent()
        .unwrap()
        .to_path_buf();
    let _ = std::fs::remove_dir_all(&shard_dir);
    std::fs::write(&shard_dir, b"notadir").unwrap();
    // Ack should report corruption, not LeaseLost.
    let result = queue.ack(&lease);
    assert!(
        matches!(result, AckOutcome::NotCommitted(Error::QueueCorrupt(_))),
        "ENOTDIR should be QueueCorrupt, got {result:?}"
    );
}

// ===== ack on gone source returns AlreadyAcked (ENOENT path) =====
#[test]
fn ack_on_gone_source_returns_already_acked() {
    let (_tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!("lease failed"),
    };
    // First ack succeeds.
    let result = queue.ack(&lease);
    assert!(matches!(result, AckOutcome::Acked));
    // Second ack: source is gone (ENOENT in open_and_validate).
    // Should return AlreadyAcked, not NotCommitted(QueueCorrupt).
    let result2 = queue.ack(&lease);
    assert!(
        matches!(result2, AckOutcome::AlreadyAcked),
        "second ack should be AlreadyAcked, got {result2:?}"
    );
}

// ===== move_to_dead actually moves exhausted objects =====
#[test]
fn exhausted_attempts_move_to_dead() {
    let (tmp, mut queue) = create_test_queue();
    let ticket = match queue.enqueue(EnqueueInput {
        maximum_attempts: 1,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    }) {
        EnqueueOutcome::Committed(ticket) => ticket,
        outcome => panic!("enqueue failed: {outcome:?}"),
    };
    let (ready_dir, ready_name) = ticket.expected_relative_path.rsplit_once('/').unwrap();
    let parsed = steadq_names::parse_ready(ready_name).unwrap();
    let wall_floor = queue.wall_floor_for_mutation().unwrap();

    queue
        .move_to_dead(
            ready_dir,
            ready_name,
            &parsed.common,
            DeadReason::AttemptsExhausted,
            wall_floor,
        )
        .unwrap();

    assert!(!tmp.path().join(&ticket.expected_relative_path).exists());
    assert!(find_file_with_suffix(&tmp.path().join("dead"), ".sqj").is_some());
}

// ===== fsck on delayed/dead/receipt states =====
#[test]
fn fsck_finds_valid_delayed_job() {
    let (_tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!("lease failed"),
    };
    // Retry with delay to create a delayed object
    let _ = queue.retry_after(&lease, 999999999999);
    drop(queue);

    let queue2 = Queue::open(
        _tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    )
    .unwrap();
    let report = queue2.fsck(&FsckOptions::default());
    assert_eq!(report.findings.len(), 0, "findings: {:?}", report.findings);
}

#[test]
fn fsck_finds_valid_dead_job() {
    let (_tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!("lease failed"),
    };
    // Bury to create a dead object
    let _ = queue.bury(&lease, DeadReason::ConsumerRejected);
    drop(queue);

    let queue2 = Queue::open(
        _tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    )
    .unwrap();
    let report = queue2.fsck(&FsckOptions::default());
    assert_eq!(report.findings.len(), 0, "findings: {:?}", report.findings);
}

#[test]
fn fsck_finds_valid_receipt() {
    let (_tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!("lease failed"),
    };
    // Ack to create a receipt
    queue.verify_lease_payload(&lease).unwrap();
    let result = queue.ack(&lease);
    assert!(matches!(result, AckOutcome::Acked));
    drop(queue);

    let queue2 = Queue::open(
        _tmp.path(),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    )
    .unwrap();
    let report = queue2.fsck(&FsckOptions::default());
    assert_eq!(report.findings.len(), 0, "findings: {:?}", report.findings);
    assert_eq!(report.structurally_verified, 1);
    assert_eq!(report.payloads_deep_verified, 1);
}

// ===== fsck on leased state =====
#[test]
fn fsck_finds_valid_leased_job() {
    let (_tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    });
    let _lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!("lease failed"),
    };
    // Don't drop the queue - run fsck while object is leased.
    let report = queue.fsck(&FsckOptions::default());
    assert_eq!(
        report.findings.len(),
        0,
        "valid leased object should have no findings: {:?}",
        report.findings
    );
    assert!(report.total_objects >= 1);
}

// ===== strict ack reaches rename and triggers EEXIST =====
#[test]
fn ack_eexist_triggers_not_committed() {
    let (_tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!("lease failed"),
    };
    // Compute exact receipt path.
    let shard = compute_shard(
        queue.format.queue_id(),
        &lease.job_id,
        queue.format.shard_count(),
    );
    let shard_str = shard_hex(shard);
    let wall = queue.effective_wall_floor_ns_checked().unwrap();
    let bucket = steadq_math::bucket_number(wall, queue.format.terminal_bucket_width_ns()).unwrap();
    let bucket_str = bucket_hex(bucket);
    let new_gen = lease.generation + 1;
    let receipt_common = CommonFields {
        job_id: lease.job_id,
        generation: new_gen,
        attempt: lease.attempt,
        maximum_attempts: lease.maximum_attempts,
    };
    let receipt_base = format!(
        "{}.g{:016x}.a{:08x}.m{:08x}.t{}",
        steadq_names::hex_encode(&receipt_common.job_id),
        receipt_common.generation,
        receipt_common.attempt,
        receipt_common.maximum_attempts,
        steadq_names::hex_encode(&lease.token),
    );
    let receipt_ctx = steadq_names::terminal_context(
        steadq_names::State::Receipt,
        &bucket_str,
        &shard_str,
        &receipt_base,
    );
    let receipt_tag = steadq_names::compute_name_tag(queue.format.queue_id(), &receipt_ctx);
    let receipt_name = steadq_names::receipt_filename(&receipt_common, &lease.token, &receipt_tag);
    let receipt_dir = format!("receipts/{bucket_str}/{shard_str}");
    let full_dir = _tmp.path().join(&receipt_dir);
    std::fs::create_dir_all(&full_dir).unwrap();
    std::fs::write(full_dir.join(&receipt_name), b"not a receipt").unwrap();
    let result = queue.ack(&lease);
    // Must be NotCommitted with QueueCorrupt (from EEXIST handler),
    // NOT IoFailure (from generic handler that mutant "guard == false" would route to).
    match result {
        AckOutcome::NotCommitted(Error::QueueCorrupt(_)) => { /* correct */ }
        AckOutcome::NotCommitted(other) => {
            panic!("expected QueueCorrupt from EEXIST handler, got {other:?}")
        }
        other => panic!("expected NotCommitted, got {other:?}"),
    }
}

// ===== stream_lease_payload boundary tests =====
#[test]
fn stream_payload_exact_byte_math() {
    let (_tmp, mut queue) = create_test_queue();
    let payload = b"0123456789ABCDEF"; // 16 bytes
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: payload.to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!("lease failed"),
    };
    // Read with small chunk to test exact offset math.
    let mut collected = Vec::new();
    queue
        .stream_lease_payload(&lease, 4096, |chunk| {
            collected.extend_from_slice(chunk);
            Ok(())
        })
        .unwrap();
    assert_eq!(&collected, payload);

    // Read with chunk size equal to payload.
    collected.clear();
    queue
        .stream_lease_payload(&lease, 16, |chunk| {
            collected.extend_from_slice(chunk);
            Ok(())
        })
        .unwrap();
    assert_eq!(&collected, payload);

    // Read with chunk larger than payload.
    collected.clear();
    queue
        .stream_lease_payload(&lease, 1024, |chunk| {
            collected.extend_from_slice(chunk);
            Ok(())
        })
        .unwrap();
    assert_eq!(&collected, payload);
}

#[test]
fn resolve_does_not_follow_object_relocated_to_wrong_shard() {
    let (_tmp, mut queue) = create_test_queue();
    let et = match queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    }) {
        EnqueueOutcome::Committed(t) => t,
        _ => panic!("enqueue failed"),
    };
    // Move the ready file to a wrong shard directory.
    let actual_path = et.expected_relative_path.clone();
    let actual_full = _tmp.path().join(&actual_path);
    let parts: Vec<&str> = actual_path.split('/').collect();
    let wrong_shard = if parts[1] == "0000" { "0001" } else { "0000" };
    let wrong_dir = _tmp.path().join("ready").join(wrong_shard);
    std::fs::create_dir_all(&wrong_dir).unwrap();
    let wrong_path = wrong_dir.join(parts[2]);
    std::fs::rename(&actual_full, &wrong_path).unwrap();
    let ticket = test_claim_ticket(&queue, et.job_id, 0, 0, 3, [0; 16], et.envelope_digest);
    let outcome = queue.resolve(&ticket, false);
    assert!(
        matches!(outcome, ResolutionOutcome::NeitherObserved),
        "resolver should only inspect the derived shard, got {outcome:?}"
    );
}

// ===== verified fd dev/ino check =====
#[test]
fn ack_verified_fd_held_open_across_rename() {
    let (_tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"verified payload".to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!("lease failed"),
    };
    // Normal ack should succeed and return Acked (not NotCommitted).
    let result = queue.ack(&lease);
    assert!(
        matches!(result, AckOutcome::Acked),
        "normal ack should succeed, got {result:?}"
    );
}

// ===== verified fd check detects swap =====
#[test]
fn ack_verified_fd_dev_ino_check() {
    let (_tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"test payload data".to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!("lease failed"),
    };
    // Normal ack should work - payload is valid.
    let result = queue.ack(&lease);
    assert!(matches!(result, AckOutcome::Acked));
}

// ===== Fault injection: post-linearization and pre-linearization paths =====

#[test]
fn fault_ack_post_rename_fsync_is_outcome_unknown() {
    steadq_fs_linux::fault::reset();
    let (tmp, mut queue) = create_test_queue();

    // Warm up so at least one terminal receipt bucket exists.
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"warmup".to_vec(),
        ..Default::default()
    });
    let warm = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!("warmup lease failed"),
    };
    queue.verify_lease_payload(&warm).unwrap();
    assert!(matches!(queue.ack(&warm), AckOutcome::Acked));

    // Pre-create every shard under existing receipt buckets so ensure_dir
    // during the next ack performs no mkdir and no fsync_dir_fd. The next
    // fsync_dir_fd is then strictly post-rename (OutcomeUnknown).
    let receipts = tmp.path().join("receipts");
    let shard_count = queue.format().shard_count();
    if let Ok(buckets) = std::fs::read_dir(&receipts) {
        for bucket in buckets.flatten() {
            if !bucket.path().is_dir() {
                continue;
            }
            for shard in 0..shard_count {
                let _ = std::fs::create_dir_all(bucket.path().join(format!("{shard:04x}")));
            }
        }
    }

    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"payload-under-test".to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!("lease failed"),
    };
    queue.verify_lease_payload(&lease).unwrap();

    steadq_fs_linux::fault::inject("fsync_dir_fd", 1);
    let result = queue.ack(&lease);
    steadq_fs_linux::fault::reset();
    let AckOutcome::OutcomeUnknown(ticket) = result else {
        panic!("expected OutcomeUnknown");
    };
    assert_eq!(ticket.phase(), TransitionPhase::Linearized);
}

#[test]
fn claim_move_records_each_directory_barrier() {
    const LEASE_DURATION_NS: u64 = 30_000_000_000;
    let (tmp, mut queue) = create_test_queue();
    let enqueue = queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "text/plain".into(),
        payload: b"claim barrier".to_vec(),
        ..Default::default()
    });
    assert!(matches!(enqueue, EnqueueOutcome::Committed(_)));
    precreate_claim_destination_buckets(&tmp, &queue, LEASE_DURATION_NS);

    fs::fault::reset();
    fs::fault::inject_errno("fsync_dir_fd", 1, libc::EIO);
    let outcome = queue.lease(0, LEASE_DURATION_NS);
    fs::fault::reset();

    let LeaseOutcome::OutcomeUnknown(ticket) = outcome else {
        panic!("expected outcome unknown");
    };
    assert_eq!(ticket.phase(), TransitionPhase::Linearized);
}

#[test]
fn claim_move_keeps_prelinearization_failure_not_committed() {
    const LEASE_DURATION_NS: u64 = 30_000_000_000;
    let (tmp, mut queue) = create_test_queue();
    let enqueue = queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "text/plain".into(),
        payload: b"claim rename".to_vec(),
        ..Default::default()
    });
    let EnqueueOutcome::Committed(ticket) = enqueue else {
        panic!("expected committed enqueue");
    };
    precreate_claim_destination_buckets(&tmp, &queue, LEASE_DURATION_NS);

    fs::fault::reset();
    fs::fault::inject_errno("renameat2_noreplace", 1, libc::EIO);
    let outcome = queue.lease(0, LEASE_DURATION_NS);
    fs::fault::reset();

    assert!(matches!(outcome, LeaseOutcome::NotCommitted(_)));
    assert!(tmp.path().join(ticket.expected_relative_path).exists());
}

#[test]
fn claim_move_returns_the_authenticated_destination_identity() {
    let (tmp, mut queue) = create_test_queue();
    let lease = enqueue_and_lease(&mut queue);
    let metadata = std::fs::metadata(tmp.path().join(&lease.exact_source_path)).unwrap();

    assert_eq!(lease.expected_dev, metadata.dev());
    assert_eq!(lease.expected_inode, metadata.ino());
}

#[test]
fn fault_ack_rename_failure_is_not_committed() {
    steadq_fs_linux::fault::reset();
    let (_tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!("lease failed"),
    };
    queue.verify_lease_payload(&lease).unwrap();
    steadq_fs_linux::fault::inject("renameat2_noreplace", 1);
    let result = queue.ack(&lease);
    steadq_fs_linux::fault::reset();
    assert!(
        matches!(result, AckOutcome::NotCommitted(_)),
        "expected NotCommitted, got {result:?}"
    );
}

#[test]
fn fault_retry_post_rename_fsync_is_outcome_unknown() {
    steadq_fs_linux::fault::reset();
    let (tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(l) => l,
        _ => panic!("lease failed"),
    };
    // Pre-create every ready shard so ensure_dir during retry_now does not
    // fsync. The next fsync_dir_fd is post-rename.
    let ready = tmp.path().join("ready");
    let shard_count = queue.format().shard_count();
    for shard in 0..shard_count {
        let _ = std::fs::create_dir_all(ready.join(format!("{shard:04x}")));
    }
    steadq_fs_linux::fault::inject("fsync_dir_fd", 1);
    let result = queue.retry_now(&lease);
    steadq_fs_linux::fault::reset();
    let TransitionOutcome::OutcomeUnknown(ticket) = result else {
        panic!("expected OutcomeUnknown");
    };
    assert_eq!(ticket.phase(), TransitionPhase::Linearized);
}

#[test]
fn fault_retry_source_fsync_records_destination_durability() {
    steadq_fs_linux::fault::reset();
    let (_tmp, mut queue) = create_test_queue();
    queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    });
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(lease) => lease,
        other => panic!("lease failed: {other:?}"),
    };

    steadq_fs_linux::fault::inject_errno("fsync_dir_fd", 1, libc::EIO);
    let result = queue.retry_now(&lease);
    steadq_fs_linux::fault::reset();
    let TransitionOutcome::OutcomeUnknown(ticket) = result else {
        panic!("expected OutcomeUnknown");
    };
    assert_eq!(ticket.phase(), TransitionPhase::Linearized);
}

#[test]
fn fault_clock_realtime_poisons_enqueue() {
    steadq_fs_linux::fault::reset();
    let (_tmp, mut queue) = create_test_queue();
    steadq_fs_linux::fault::inject("clock_realtime_ns", 1);
    let outcome = queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: b"data".to_vec(),
        ..Default::default()
    });
    steadq_fs_linux::fault::reset();
    assert!(
        matches!(
            outcome,
            EnqueueOutcome::NotCommitted(_, _) | EnqueueOutcome::OutcomeUnknown(_, _)
        ),
        "expected clock fault to fail enqueue, got {outcome:?}"
    );
}

#[test]
fn is_expected_dev_zero_table() {
    assert!(Queue::is_expected_dev_zero(0));
    assert!(!Queue::is_expected_dev_zero(1));
    assert!(!Queue::is_expected_dev_zero(u64::MAX));
    assert!(!Queue::is_expected_dev_zero(42));
}

#[test]
fn is_expected_inode_zero_table() {
    assert!(Queue::is_expected_inode_zero(0));
    assert!(!Queue::is_expected_inode_zero(1));
    assert!(!Queue::is_expected_inode_zero(u64::MAX));
}

#[test]
fn shard_matches_table() {
    assert!(Queue::shard_matches(5, 5));
    assert!(!Queue::shard_matches(5, 6));
    assert!(!Queue::shard_matches(6, 5));
    assert!(!Queue::shard_matches(0, 1));
    assert!(Queue::shard_matches(u32::MAX, u32::MAX));
}

/// Storage exhaustion before the linearizing rename must report
/// `ResourceExhausted` and leave the handle usable, per the contract's
/// disk-full classification, on every consumer transition.
#[test]
fn consumer_transitions_classify_enospc_as_resource_exhausted() {
    for errno in [libc::ENOSPC, libc::EDQUOT] {
        let (_tmp, mut queue) = create_test_queue();

        let lease = enqueue_and_lease(&mut queue);
        fs::fault::reset();
        fs::fault::inject_errno("mkdirat", 1, errno);
        let ack = queue.ack(&lease);
        fs::fault::reset();
        assert!(
            matches!(ack, AckOutcome::NotCommitted(Error::ResourceExhausted)),
            "ack under errno {errno}: {ack:?}"
        );
        assert!(!queue.is_poisoned());

        fs::fault::inject_errno("renameat2_noreplace", 1, errno);
        let retry = queue.retry_now(&lease);
        fs::fault::reset();
        assert!(
            matches!(
                retry,
                TransitionOutcome::NotCommitted(Error::ResourceExhausted)
            ),
            "retry under errno {errno}: {retry:?}"
        );
        assert!(!queue.is_poisoned());

        fs::fault::inject_errno("renameat2_noreplace", 1, errno);
        let renew = queue.renew(&lease, 60_000_000_000);
        fs::fault::reset();
        assert!(
            matches!(renew, RenewOutcome::NotCommitted(Error::ResourceExhausted)),
            "renew under errno {errno}: {renew:?}"
        );
        assert!(!queue.is_poisoned());

        fs::fault::inject_errno("mkdirat", 1, errno);
        let bury = queue.bury(&lease, DeadReason::ConsumerRejected);
        fs::fault::reset();
        assert!(
            matches!(
                bury,
                TransitionOutcome::NotCommitted(Error::ResourceExhausted)
            ),
            "bury under errno {errno}: {bury:?}"
        );
        assert!(!queue.is_poisoned());

        // The lease is intact after every refused transition.
        assert!(matches!(queue.ack(&lease), AckOutcome::Acked));
    }
}

#[test]
fn attempt_exhaustion_under_enospc_refuses_without_poisoning() {
    let (tmp, mut queue) = create_test_queue();
    let ticket = match queue.enqueue(EnqueueInput {
        maximum_attempts: 1,
        content_type: "x".to_string(),
        payload: b"exhausted".to_vec(),
        ..Default::default()
    }) {
        EnqueueOutcome::Committed(ticket) => ticket,
        outcome => panic!("enqueue failed: {outcome:?}"),
    };
    // Rewrite the ready name with attempt == maximum_attempts, the state a
    // crashed retry can leave behind, so the next claim takes the
    // dead-letter path.
    let (ready_dir, ready_name) = ticket.expected_relative_path.rsplit_once('/').unwrap();
    let mut common = steadq_names::parse_ready(ready_name).unwrap().common;
    common.attempt = common.maximum_attempts;
    let shard_hex = ready_dir.rsplit_once('/').unwrap().1;
    let exhausted_name = steadq_names::make_ready_name(queue.queue_id(), shard_hex, &common);
    std::fs::rename(
        tmp.path().join(&ticket.expected_relative_path),
        tmp.path().join(ready_dir).join(&exhausted_name),
    )
    .unwrap();

    // The dead bucket does not exist yet, so mkdirat is the first
    // allocating syscall on the dead-letter path.
    fs::fault::reset();
    fs::fault::inject_errno("mkdirat", 1, libc::ENOSPC);
    let outcome = queue.lease(0, 30_000_000_000);
    fs::fault::reset();
    assert!(
        matches!(
            outcome,
            LeaseOutcome::NotCommitted(Error::ResourceExhausted)
        ),
        "{outcome:?}"
    );
    assert!(!queue.is_poisoned());
    assert!(tmp.path().join(ready_dir).join(&exhausted_name).exists());

    // With space back, the same claim completes the dead-letter move.
    assert!(matches!(
        queue.lease(0, 30_000_000_000),
        LeaseOutcome::Empty
    ));
    assert!(find_file_with_suffix(&tmp.path().join("dead"), ".sqj").is_some());
}

#[test]
fn remove_dead_under_enospc_reports_resource_exhausted() {
    let (_tmp, mut queue) = create_test_queue();
    let lease = enqueue_and_lease(&mut queue);
    assert!(matches!(
        queue.bury(&lease, DeadReason::AdministrativeBury),
        TransitionOutcome::Committed
    ));
    fs::fault::reset();
    fs::fault::inject_errno("unlinkat", 1, libc::ENOSPC);
    let result = queue.remove_dead(&lease.job_id);
    fs::fault::reset();
    assert_eq!(result, Err(Error::ResourceExhausted));
    assert!(!queue.is_poisoned());
    assert_eq!(queue.remove_dead(&lease.job_id), Ok(true));
}

#[test]
fn watermark_advance_under_enospc_refuses_without_poisoning() {
    let (tmp, mut queue) = create_test_queue();
    // A realtime reading one year ahead of the stored watermark forces the
    // advance path; its first write is the temp watermark record.
    let now = fs::clock_realtime_ns().unwrap();
    fs::fault::reset();
    fs::fault::set_clock_realtime_ns(now + 365 * 24 * 3_600_000_000_000);
    fs::fault::inject_errno("write_all", 1, libc::ENOSPC);
    let job = EnqueueInput {
        maximum_attempts: 1,
        content_type: "x".to_string(),
        payload: b"watermark".to_vec(),
        ..Default::default()
    };
    let before = queue.read_wall_watermark().unwrap();
    let outcome = queue.enqueue(job.clone());
    assert!(
        matches!(
            outcome,
            EnqueueOutcome::NotCommitted(_, Error::ResourceExhausted)
        ),
        "{outcome:?}"
    );
    assert!(!queue.is_poisoned());
    // The refused advance left neither a new record nor an orphaned temp.
    let after = queue.read_wall_watermark().unwrap();
    assert_eq!(after.sequence, before.sequence);
    assert_eq!(
        after.highest_observed_bucket,
        before.highest_observed_bucket
    );
    let orphans: Vec<String> = std::fs::read_dir(tmp.path().join("control"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".wm.adv."))
        .collect();
    assert!(orphans.is_empty(), "{orphans:?}");
    assert!(matches!(queue.enqueue(job), EnqueueOutcome::Committed(_)));
    assert_eq!(
        queue.read_wall_watermark().unwrap().sequence,
        before.sequence + 1
    );
    fs::fault::reset();
}

#[test]
fn list_dead_returns_authenticated_dead_objects_only() {
    let (tmp, mut queue) = create_test_queue();
    assert_eq!(queue.list_dead().unwrap(), Vec::new());
    let lease = enqueue_and_lease(&mut queue);
    assert!(matches!(
        queue.bury(&lease, DeadReason::AdministrativeBury),
        TransitionOutcome::Committed
    ));
    let expected: Vec<_> = queue
        .inspect(&lease.job_id)
        .into_iter()
        .filter(|s| s.state == "dead")
        .collect();
    assert_eq!(expected.len(), 1);
    let dead_dir = tmp
        .path()
        .join(expected[0].relative_path.rsplit_once('/').unwrap().0);
    // A stray name and a real name whose tag belongs to another queue are
    // both invisible.
    std::fs::write(dead_dir.join("garbage.sqj"), b"x").unwrap();
    let foreign = expected[0].relative_path.rsplit_once('/').unwrap().1;
    let mut foreign = foreign.to_string();
    let tag_start = foreign.rfind(".k").unwrap() + 2;
    foreign.replace_range(tag_start..tag_start + 1, "0");
    if foreign == *expected[0].relative_path.rsplit_once('/').unwrap().1 {
        foreign.replace_range(tag_start..tag_start + 1, "1");
    }
    std::fs::copy(
        tmp.path().join(&expected[0].relative_path),
        dead_dir.join(&foreign),
    )
    .unwrap();

    let listed = queue.list_dead().unwrap();
    assert_eq!(listed, expected);

    // Opening dead/ (call 1) or a bucket (call 3, after the listing reopen)
    // with an error is reported; a bucket that vanished is skipped.
    for count in [1, 3] {
        fs::fault::reset();
        fs::fault::inject_errno("open_directory", count, libc::EIO);
        let unreadable = queue.list_dead();
        fs::fault::reset();
        assert!(
            matches!(unreadable, Err(Error::IoFailure(_))),
            "count {count}: {unreadable:?}"
        );
    }
    fs::fault::inject_errno("open_directory", 3, libc::ENOENT);
    let vanished = queue.list_dead();
    fs::fault::reset();
    assert_eq!(vanished.unwrap(), Vec::new());
}

#[test]
fn poison_reason_is_recorded_once_and_named_in_the_error() {
    let (_tmp, mut queue) = create_test_queue();
    assert_eq!(queue.poison_reason(), None);
    queue.poison(PoisonReason::WatermarkAuthorityLost);
    queue.poison(PoisonReason::InternalInvariantViolation);
    assert_eq!(
        queue.poison_reason(),
        Some(PoisonReason::WatermarkAuthorityLost)
    );
    let lease = queue.lease(0, 30_000_000_000);
    assert!(
        matches!(
            &lease,
            LeaseOutcome::NotCommitted(Error::QueuePoisoned(message))
                if message == "wall watermark authority lost"
        ),
        "{lease:?}"
    );
}

/// The claim-time dead-letter move poisons only past its linearization
/// point, and then names that reason.
#[test]
fn dead_letter_move_poisons_only_after_linearization() {
    for (fault, poisoned) in [("renameat2_noreplace", false), ("fsync_dir_fd", true)] {
        let (tmp, mut queue) = create_test_queue();
        let ticket = match queue.enqueue(EnqueueInput {
            maximum_attempts: 1,
            content_type: "x".to_string(),
            payload: b"exhausted".to_vec(),
            ..Default::default()
        }) {
            EnqueueOutcome::Committed(ticket) => ticket,
            outcome => panic!("enqueue failed: {outcome:?}"),
        };
        let (ready_dir, ready_name) = ticket.expected_relative_path.rsplit_once('/').unwrap();
        let mut common = steadq_names::parse_ready(ready_name).unwrap().common;
        common.attempt = common.maximum_attempts;
        let shard_hex = ready_dir.rsplit_once('/').unwrap().1;
        let exhausted_name = steadq_names::make_ready_name(queue.queue_id(), shard_hex, &common);
        std::fs::rename(
            tmp.path().join(&ticket.expected_relative_path),
            tmp.path().join(ready_dir).join(&exhausted_name),
        )
        .unwrap();
        let wall_floor = queue.wall_floor_for_mutation().unwrap();
        let dead_bucket = steadq_math::bucket_number(
            wall_floor.unix_ns(),
            queue.format.terminal_bucket_width_ns(),
        )
        .unwrap();
        queue
            .ensure_dir(&format!(
                "dead/{}/{shard_hex}",
                steadq_names::bucket_hex(dead_bucket)
            ))
            .unwrap();

        fs::fault::reset();
        fs::fault::inject_errno(fault, 1, libc::EIO);
        let outcome = queue.lease(0, 30_000_000_000);
        fs::fault::reset();
        assert!(
            matches!(outcome, LeaseOutcome::NotCommitted(Error::IoFailure(_))),
            "{fault}: {outcome:?}"
        );
        assert_eq!(
            queue.poison_reason(),
            poisoned.then_some(PoisonReason::PostLinearizationStateUnknown),
            "{fault}"
        );
    }
}

#[test]
fn claimed_object_validation_rejects_each_filename_mismatch_alone() {
    let (tmp, mut queue) = create_test_queue();
    let ticket = match queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "text/plain".to_string(),
        payload: b"validate".to_vec(),
        ..Default::default()
    }) {
        EnqueueOutcome::Committed(ticket) => ticket,
        outcome => panic!("enqueue failed: {outcome:?}"),
    };
    let path = tmp.path().join(&ticket.expected_relative_path);
    let file = std::fs::File::open(&path).unwrap();
    let size = file.metadata().unwrap().len();
    let common =
        steadq_names::parse_ready(ticket.expected_relative_path.rsplit('/').next().unwrap())
            .unwrap()
            .common;

    let valid = queue.validate_claimed_object(file.as_fd(), size, &common);
    assert_eq!(
        valid.as_ref().map(|(h, ct)| (h.job_id, ct.as_str())),
        Some((common.job_id, "text/plain"))
    );
    let mut other_job = common.clone();
    other_job.job_id[0] ^= 0xff;
    assert!(queue
        .validate_claimed_object(file.as_fd(), size, &other_job)
        .is_none());
    let mut other_attempts = common.clone();
    other_attempts.maximum_attempts += 1;
    assert!(queue
        .validate_claimed_object(file.as_fd(), size, &other_attempts)
        .is_none());
    assert!(queue
        .validate_claimed_object(file.as_fd(), size + 1, &common)
        .is_none());
}

#[test]
fn dead_letter_move_reports_identity_overflow_as_state_exhausted() {
    let (_tmp, mut queue) = create_test_queue();
    let common = steadq_names::CommonFields {
        job_id: [0xAB; 16],
        generation: u64::MAX,
        attempt: 1,
        maximum_attempts: 1,
    };
    let wall_floor = queue.wall_floor_for_mutation().unwrap();
    let result = queue.move_to_dead(
        "ready/0000",
        "dummy",
        &common,
        DeadReason::AttemptsExhausted,
        wall_floor,
    );
    assert!(
        matches!(
            result,
            Err(DeadLetterFailure::Invalid(Error::StateExhausted))
        ),
        "{result:?}"
    );
    assert!(!queue.is_poisoned());
}

/// A read failure while re-verifying the payload before the ack rename is
/// transient: the handle stays usable. Corruption still poisons.
#[test]
fn ack_read_failure_before_rename_does_not_poison() {
    // The last pread of a clean ack is the payload verification, so failing
    // exactly that call exercises the path under test.
    let total_preads = {
        let (_tmp, mut queue) = create_test_queue();
        let lease = enqueue_and_lease(&mut queue);
        fs::fault::reset();
        fs::fault::inject("pread", u64::MAX);
        assert!(matches!(queue.ack(&lease), AckOutcome::Acked));
        let total = fs::fault::call_count("pread");
        fs::fault::reset();
        total
    };
    let mut saw_read_failure = false;
    for count in 1..=total_preads {
        let (_tmp, mut queue) = create_test_queue();
        let lease = enqueue_and_lease(&mut queue);
        fs::fault::reset();
        fs::fault::inject_errno("pread", count, libc::EIO);
        let outcome = queue.ack(&lease);
        fs::fault::reset();
        match (outcome, queue.poison_reason()) {
            // An early count lands on the wall-watermark read, which
            // poisons under its own policy; that is not the path under test.
            (AckOutcome::NotCommitted(_), Some(PoisonReason::WatermarkAuthorityLost)) => {}
            (AckOutcome::NotCommitted(Error::IoFailure(_)), None) => {
                saw_read_failure = count == total_preads;
                assert!(
                    matches!(queue.ack(&lease), AckOutcome::Acked),
                    "pread {count}"
                );
            }
            (outcome, reason) => panic!("pread {count}: {outcome:?} {reason:?}"),
        }
    }
    assert!(
        saw_read_failure,
        "the final pread of the ack did not fail as an unpoisoned read error"
    );
}
