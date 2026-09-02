// SteadQ/1 cooperative recovery operations.

use std::io;
use std::os::unix::io::{AsFd, BorrowedFd, OwnedFd};

use steadq_fs_linux as fs;
use steadq_math;
use steadq_names;

use crate::errors::*;
use crate::queue::engine::{
    move_verified_noreplace, remove_empty_directory_verified, replace_verified, unlink_verified,
    MoveFailure, MovePhase, RemoveDirectoryFailure, ReplaceFailure, ReplaceIdentity, UnlinkFailure,
};
use crate::queue::{
    open_relative, FourLevelCursor, Queue, RecoveryCursor, RecoveryHierarchyRetry,
    RecoveryHierarchyRetryKind, RecoveryPhase, ThreeLevelCursor, WallFloor,
};

const RECOVERY_CURSOR_SCHEMA: &str = "steadq-recovery-cursor";
const RECOVERY_CURSOR_VERSION: u16 = 1;
const RECOVERY_CURSOR_FILE: &str = "recovery-cursor.json";
const RECOVERY_CURSOR_MAX_BYTES: u64 = 16 * 1024;
const RECOVERY_CURSOR_OPEN_FLAGS: i32 = libc::O_CLOEXEC + libc::O_NOFOLLOW;
const RECOVERY_LOCK_OPEN_FLAGS: i32 = libc::O_CLOEXEC + libc::O_NOFOLLOW + libc::O_RDWR;
const MAX_RECOVERY_DIRECTORY_ENTRIES: usize = 65_536;
const MAX_RECOVERY_DIRECTORY_NAME_BYTES: usize = MAX_RECOVERY_DIRECTORY_ENTRIES * 255;
const MAX_RECOVERY_DIRECTORY_ENTRY_CHARGE: u64 = MAX_RECOVERY_DIRECTORY_ENTRIES as u64 + 1;
const MAX_RECOVERY_DIRECTORY_NAME_BYTE_CHARGE: u64 = MAX_RECOVERY_DIRECTORY_NAME_BYTES as u64 + 255;
const MAX_RECOVERY_HIERARCHY_RETRIES: usize = 64;
const MAX_RECOVERY_RESUMED_TRAVERSAL_READS: u64 = 4;
const RECOVERY_RETRY_READS: u64 = 1;
const MIN_RECOVERY_PROGRESS_READS: u64 =
    MAX_RECOVERY_RESUMED_TRAVERSAL_READS + RECOVERY_RETRY_READS;
const MIN_RECOVERY_PROGRESS_ENTRIES: u64 =
    MAX_RECOVERY_DIRECTORY_ENTRIES as u64 * MIN_RECOVERY_PROGRESS_READS + 1;
const MIN_RECOVERY_PROGRESS_NAME_BYTES: u64 =
    MAX_RECOVERY_DIRECTORY_NAME_BYTES as u64 * MIN_RECOVERY_PROGRESS_READS + 255;
const DEFAULT_RECOVERY_DIRECTORY_READS: u64 = 1024;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryCursorRecord {
    schema: String,
    version: u16,
    queue_id: String,
    cursor: RecoveryCursor,
}

fn cursor_component_is_valid(component: &[u8]) -> bool {
    !component.is_empty()
        && component.len() <= 255
        && component != b"."
        && component != b".."
        && !component.contains(&b'/')
        && !component.contains(&b'\0')
}

fn read_recovery_directory(
    dir_fd: BorrowedFd<'_>,
    deadline_mono: u64,
    budget: &RecoveryScanBudget,
    stats: &mut RecoveryScanStats,
) -> Result<Vec<fs::DirEntryName>, RecoveryDirectoryError> {
    if stats.directories_read >= budget.max_directories_read {
        return Err(RecoveryDirectoryError::BudgetExhausted);
    }
    let remaining_entries = budget.max_entries_read.saturating_sub(stats.entries_read);
    let remaining_name_bytes = budget
        .max_name_bytes_read
        .saturating_sub(stats.name_bytes_read);
    if remaining_entries < MAX_RECOVERY_DIRECTORY_ENTRY_CHARGE
        || remaining_name_bytes < MAX_RECOVERY_DIRECTORY_NAME_BYTE_CHARGE
    {
        return Err(RecoveryDirectoryError::BudgetExhausted);
    }
    stats.directories_read = stats.directories_read.saturating_add(1);

    let result = fs::read_dir_entries_bounded_until_with_progress(
        dir_fd,
        MAX_RECOVERY_DIRECTORY_ENTRIES,
        MAX_RECOVERY_DIRECTORY_NAME_BYTES,
        || Queue::budget_time_exceeded(deadline_mono),
    );
    let progress = match &result {
        Ok(enumeration) => enumeration.progress,
        Err(error) => error.progress(),
    };
    let entries_read = u64::try_from(progress.entries_read).unwrap_or(u64::MAX);
    let name_bytes_read = u64::try_from(progress.name_bytes_read).unwrap_or(u64::MAX);
    stats.entries_read = stats.entries_read.saturating_add(entries_read);
    stats.name_bytes_read = stats.name_bytes_read.saturating_add(name_bytes_read);

    result
        .map(|enumeration| enumeration.entries)
        .map_err(|error| match error {
            fs::DirectoryEnumerationProgressError::Cancelled(_) => {
                RecoveryDirectoryError::BudgetExhausted
            }
            fs::DirectoryEnumerationProgressError::CancellationCheck { error, .. } => {
                RecoveryDirectoryError::Clock(error)
            }
            fs::DirectoryEnumerationProgressError::Io { error, .. } => {
                RecoveryDirectoryError::Io(error)
            }
        })
}

#[derive(Debug)]
enum RecoveryDirectoryError {
    BudgetExhausted,
    Clock(io::Error),
    Io(io::Error),
}

struct RecoveryQuarantineCandidate<'a> {
    source_directory_fd: BorrowedFd<'a>,
    filename: &'a str,
    relative_path: &'a str,
    reason: crate::QuarantineReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RememberHierarchyRetry {
    Exact,
    Overflow,
    Invalid,
}

fn raw_name_for_error(name: &fs::DirEntryName) -> String {
    format!("{name:?}")
}

fn all_observed_children_absent(absent: usize, observed: usize) -> bool {
    absent == observed
}

fn cursor_is_valid(cursor: &RecoveryCursor) -> bool {
    let three_level_is_valid = |scan: &ThreeLevelCursor| {
        cursor_component_is_valid(&scan.first)
            && cursor_component_is_valid(&scan.second)
            && cursor_component_is_valid(&scan.resume_after)
    };
    let four_level_is_valid = |scan: &FourLevelCursor| {
        [&scan.first, &scan.second, &scan.third, &scan.resume_after]
            .into_iter()
            .all(|component| cursor_component_is_valid(component))
    };

    let retry_depth_is_valid = |retry: &RecoveryHierarchyRetry| {
        let allowed_depth = match retry.phase {
            RecoveryPhase::ReapLeases => 1..=3,
            RecoveryPhase::PromoteDelayed
            | RecoveryPhase::CleanupTemp
            | RecoveryPhase::CompactReceipts
            | RecoveryPhase::DeleteReceipts => 1..=2,
        };
        if !allowed_depth.contains(&retry.components.len()) {
            return false;
        }
        retry
            .components
            .iter()
            .enumerate()
            .all(|(index, component)| match retry.phase {
                RecoveryPhase::ReapLeases => match index {
                    0 => steadq_names::boot_id_bytes(component).is_some(),
                    1 => steadq_names::bucket_from_hex(component).is_some(),
                    2 => steadq_names::shard_from_hex(component).is_some(),
                    _ => false,
                },
                RecoveryPhase::CleanupTemp => match index {
                    0 => steadq_names::boot_id_bytes(component).is_some(),
                    1 => steadq_names::shard_from_hex(component).is_some(),
                    _ => false,
                },
                RecoveryPhase::PromoteDelayed
                | RecoveryPhase::CompactReceipts
                | RecoveryPhase::DeleteReceipts => match index {
                    0 => steadq_names::bucket_from_hex(component).is_some(),
                    1 => steadq_names::shard_from_hex(component).is_some(),
                    _ => false,
                },
            })
    };

    cursor.reap_leases.as_ref().is_none_or(four_level_is_valid)
        && cursor
            .promote_delayed
            .as_ref()
            .is_none_or(three_level_is_valid)
        && cursor
            .cleanup_temp
            .as_ref()
            .is_none_or(three_level_is_valid)
        && cursor
            .compact_receipts
            .as_ref()
            .is_none_or(three_level_is_valid)
        && cursor
            .delete_receipts
            .as_ref()
            .is_none_or(three_level_is_valid)
        && cursor.hierarchy_retries.len() <= MAX_RECOVERY_HIERARCHY_RETRIES
        && cursor.hierarchy_retries.iter().all(retry_depth_is_valid)
        && cursor
            .hierarchy_retries
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        && cursor.hierarchy_retry_frontiers.len() <= 5
        && cursor
            .hierarchy_retry_frontiers
            .iter()
            .all(retry_depth_is_valid)
        && cursor
            .hierarchy_retry_frontiers
            .windows(2)
            .all(|pair| pair[0].phase < pair[1].phase)
        && cursor
            .hierarchy_retry_overflow
            .windows(2)
            .all(|pair| pair[0] < pair[1])
}

fn cursor_file_metadata_is_valid(mode: libc::mode_t, link_count: libc::nlink_t) -> bool {
    mode & libc::S_IFMT == libc::S_IFREG && link_count == 1
}

fn cursor_record_size_is_valid(size: u64) -> bool {
    (1..=RECOVERY_CURSOR_MAX_BYTES).contains(&size)
}

fn cursor_record_version_is_supported(record: &RecoveryCursorRecord) -> bool {
    record.schema == RECOVERY_CURSOR_SCHEMA && record.version == RECOVERY_CURSOR_VERSION
}

fn cursor_record_bytes_fit(size: usize) -> bool {
    u64::try_from(size).is_ok_and(cursor_record_size_is_valid)
}

fn cursor_file_is_absent(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::ENOENT)
}

fn compaction_temporary_name(name: &str) -> bool {
    let Some(random_hex) = name
        .strip_prefix(".compact-")
        .and_then(|name| name.strip_suffix(".tmp"))
    else {
        return false;
    };
    random_hex.len() == 32
        && random_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn recovery_lock_exists(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::AlreadyExists
}

pub(crate) fn load_recovery_cursor(
    root_fd: BorrowedFd<'_>,
    queue_id: &[u8; 16],
) -> Result<RecoveryCursor, Error> {
    let control_fd = fs::open_directory(root_fd, "control").map_err(Error::from)?;
    let cursor_fd = match fs::openat(
        control_fd.as_fd(),
        RECOVERY_CURSOR_FILE,
        RECOVERY_CURSOR_OPEN_FLAGS,
        0,
    ) {
        Ok(fd) => fd,
        Err(error) if cursor_file_is_absent(&error) => {
            return Ok(RecoveryCursor::default());
        }
        Err(error) => return Err(Error::from(error)),
    };
    let stat = fs::fstat(cursor_fd.as_fd()).map_err(Error::from)?;
    if !cursor_file_metadata_is_valid(stat.st_mode, stat.st_nlink) {
        return Err(Error::QueueCorrupt(
            "recovery cursor is not a singly linked regular file".into(),
        ));
    }
    let size = u64::try_from(stat.st_size)
        .map_err(|_| Error::QueueCorrupt("recovery cursor has negative size".into()))?;
    if !cursor_record_size_is_valid(size) {
        return Err(Error::QueueCorrupt(
            "recovery cursor size is invalid".into(),
        ));
    }
    let mut bytes = vec![
        0;
        usize::try_from(size).map_err(|_| Error::QueueCorrupt(
            "recovery cursor size is unsupported".into()
        ))?
    ];
    fs::pread_exact(cursor_fd.as_fd(), &mut bytes, 0).map_err(Error::from)?;
    let record: RecoveryCursorRecord = serde_json::from_slice(&bytes)
        .map_err(|error| Error::QueueCorrupt(format!("recovery cursor decode: {error}")))?;
    if !cursor_record_version_is_supported(&record) {
        return Err(Error::QueueCorrupt(
            "recovery cursor schema or version is unsupported".into(),
        ));
    }
    if record.queue_id != steadq_names::hex_encode(queue_id) {
        return Err(Error::QueueCorrupt(
            "recovery cursor belongs to another queue".into(),
        ));
    }
    if !cursor_is_valid(&record.cursor) {
        return Err(Error::QueueCorrupt(
            "recovery cursor contains an invalid component".into(),
        ));
    }
    Ok(record.cursor)
}

/// Recovery work budget.
#[derive(Clone, Debug)]
pub struct WorkBudget {
    /// Maximum state-changing filesystem operations attempted after an entry
    /// has passed syntax, eligibility, locking, and identity checks.
    pub max_operations: u32,
    pub max_duration_ms: u64,
}

/// Recovery directory-enumeration budget.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryScanBudget {
    /// Maximum directory enumerations attempted during the pass.
    ///
    /// Public recovery requires one retry enumeration plus four canonical
    /// enumerations to resume its deepest hierarchy.
    pub max_directories_read: u64,
    /// Maximum protocol-visible directory entries returned by `readdir`.
    ///
    /// Enumeration starts only when the remaining budget can cover one
    /// complete bounded directory plus the sentinel entry needed to prove
    /// overflow. Public recovery requires enough capacity for the deepest
    /// resumed traversal plus one hierarchy retry.
    pub max_entries_read: u64,
    /// Maximum raw filename bytes across protocol-visible directory entries.
    ///
    /// Enumeration starts only when the remaining budget can cover one
    /// complete bounded directory plus the sentinel name needed to prove
    /// overflow. Public recovery requires enough capacity for the deepest
    /// resumed traversal plus one hierarchy retry.
    pub max_name_bytes_read: u64,
}

impl Default for WorkBudget {
    fn default() -> Self {
        Self {
            max_operations: 1000,
            max_duration_ms: 100,
        }
    }
}

impl Default for RecoveryScanBudget {
    fn default() -> Self {
        Self {
            max_directories_read: DEFAULT_RECOVERY_DIRECTORY_READS,
            ..Self::minimum_for_progress()
        }
    }
}

impl RecoveryScanBudget {
    /// Smallest scan budget that can resume the deepest hierarchy and retry
    /// one deferred directory in the same pass.
    pub fn minimum_for_progress() -> Self {
        Self {
            max_directories_read: MIN_RECOVERY_PROGRESS_READS,
            max_entries_read: MIN_RECOVERY_PROGRESS_ENTRIES,
            max_name_bytes_read: MIN_RECOVERY_PROGRESS_NAME_BYTES,
        }
    }

    /// Validate that this budget can make bounded recovery progress.
    pub fn validate(&self) -> Result<(), Error> {
        if self.max_directories_read < MIN_RECOVERY_PROGRESS_READS {
            return Err(Error::InvalidInput(format!(
                "recovery max_directories_read must be at least {MIN_RECOVERY_PROGRESS_READS}"
            )));
        }
        if self.max_entries_read < MIN_RECOVERY_PROGRESS_ENTRIES {
            return Err(Error::InvalidInput(format!(
                "recovery max_entries_read must be at least {MIN_RECOVERY_PROGRESS_ENTRIES}"
            )));
        }
        if self.max_name_bytes_read < MIN_RECOVERY_PROGRESS_NAME_BYTES {
            return Err(Error::InvalidInput(format!(
                "recovery max_name_bytes_read must be at least {MIN_RECOVERY_PROGRESS_NAME_BYTES}"
            )));
        }
        Ok(())
    }
}

/// Recovery statistics.
#[derive(Clone, Debug, Default)]
pub struct RecoveryStats {
    /// State-changing filesystem operations attempted after classification.
    pub operations_attempted: u32,
    pub temp_files_deleted: u32,
    pub delayed_promoted: u32,
    pub leases_reaped: u32,
    pub leases_to_dead: u32,
    pub buckets_removed: u32,
    pub shards_removed: u32,
    pub receipts_compacted: u32,
    pub receipts_expired: u32,
    pub quarantined: Vec<RecoveryQuarantine>,
    pub budget_exhausted: bool,
    pub phase_blocked: bool,
    pub errors: Vec<RecoveryError>,
    pub scan_skips: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryQuarantine {
    pub relative_path: String,
    pub quarantine_id: [u8; 16],
    pub quarantine_name: String,
}

/// Exact directory-enumeration work completed by a recovery pass.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RecoveryScanStats {
    pub directories_read: u64,
    pub entries_read: u64,
    pub name_bytes_read: u64,
}

/// Recovery results including scan accounting from the extended API.
#[derive(Clone, Debug, Default)]
pub struct RecoveryReport {
    pub stats: RecoveryStats,
    pub scan: RecoveryScanStats,
}

pub(crate) struct RecoveryScanContext<'a> {
    budget: &'a RecoveryScanBudget,
    stats: &'a mut RecoveryScanStats,
}

#[derive(Clone, Debug)]
pub struct RecoveryError {
    pub operation: String,
    pub relative_path: String,
    pub error: String,
}

impl Queue {
    fn acquire_recovery_lock(&self) -> Result<OwnedFd, Error> {
        let control_fd = fs::open_directory(self.root_fd(), "control").map_err(Error::from)?;
        let lock_fd = match fs::create_exclusive(control_fd.as_fd(), "recovery.lock", 0o600) {
            Ok(fd) => {
                fs::fsync(fd.as_fd()).map_err(Error::from)?;
                fs::fsync_dir_fd(control_fd.as_fd()).map_err(Error::from)?;
                fd
            }
            Err(error) if recovery_lock_exists(&error) => fs::openat(
                control_fd.as_fd(),
                "recovery.lock",
                RECOVERY_LOCK_OPEN_FLAGS,
                0,
            )
            .map_err(Error::from)?,
            Err(error) => return Err(Error::from(error)),
        };
        if !fs::try_ofd_write_lock(lock_fd.as_fd()).map_err(Error::from)? {
            return Err(Error::MaintenanceBusy);
        }
        Ok(lock_fd)
    }

    fn persist_recovery_cursor(&self) -> Result<(), Error> {
        let record = RecoveryCursorRecord {
            schema: RECOVERY_CURSOR_SCHEMA.to_string(),
            version: RECOVERY_CURSOR_VERSION,
            queue_id: steadq_names::hex_encode(self.format.queue_id()),
            cursor: self.recovery_cursor.clone(),
        };
        let bytes = serde_json::to_vec(&record)
            .map_err(|error| Error::IoFailure(format!("recovery cursor encode: {error}")))?;
        if !cursor_record_bytes_fit(bytes.len()) {
            return Err(Error::InvalidInput(
                "recovery cursor exceeds maximum encoded size".into(),
            ));
        }
        let control_fd = fs::open_directory(self.root_fd(), "control").map_err(|error| {
            Error::IoFailure(format!(
                "recovery cursor publication not committed at phase=ControlOpen: {error}"
            ))
        })?;
        let temp_name = format!(
            ".recovery-cursor.{}.tmp",
            steadq_names::hex_encode(&fs::random_128bit().map_err(|error| {
                Error::IoFailure(format!(
                    "recovery cursor publication not committed at phase=TempName: {error}"
                ))
            })?)
        );
        let temp_fd =
            fs::create_exclusive(control_fd.as_fd(), &temp_name, 0o600).map_err(|error| {
                Error::IoFailure(format!(
                    "recovery cursor publication not committed at phase=TempCreate: {error}"
                ))
            })?;
        if let Err(error) = fs::write_all(temp_fd.as_fd(), &bytes) {
            return Err(Self::cleanup_cursor_temporary_file(
                control_fd.as_fd(),
                &temp_name,
                format!("recovery cursor publication not committed at phase=TempWrite: {error}"),
            ));
        }
        if let Err(error) = fs::fsync(temp_fd.as_fd()) {
            return Err(Self::cleanup_cursor_temporary_file(
                control_fd.as_fd(),
                &temp_name,
                format!("recovery cursor publication not committed at phase=TempFsync: {error}"),
            ));
        }

        match replace_verified(
            control_fd.as_fd(),
            &temp_name,
            control_fd.as_fd(),
            RECOVERY_CURSOR_FILE,
            None,
        ) {
            Ok(()) => Ok(()),
            Err(failure) => {
                let outcome_unknown = failure.is_outcome_unknown();
                let failure = Self::cursor_replace_failure(failure);
                if outcome_unknown {
                    Err(Error::IoFailure(failure))
                } else {
                    Err(Self::cleanup_cursor_temporary_file(
                        control_fd.as_fd(),
                        &temp_name,
                        failure,
                    ))
                }
            }
        }
    }

    fn cursor_replace_failure(failure: ReplaceFailure) -> String {
        match failure {
            ReplaceFailure::NotCommitted { phase, source } => format!(
                "recovery cursor replacement not committed at phase={phase:?}: {source}"
            ),
            ReplaceFailure::OutcomeUnknown { phase, source } => format!(
                "recovery cursor replacement outcome unknown at phase={phase:?}: {source}"
            ),
            ReplaceFailure::SourceMissing => {
                "recovery cursor replacement not committed at phase=Rename: source is missing"
                    .into()
            }
            ReplaceFailure::DestinationChanged => {
                "recovery cursor replacement not committed at phase=DestinationIdentity: destination identity changed"
                    .into()
            }
        }
    }

    fn cleanup_cursor_temporary_file(
        control_fd: BorrowedFd<'_>,
        temp_name: &str,
        primary_failure: String,
    ) -> Error {
        match unlink_verified(control_fd, temp_name) {
            Ok(()) | Err(UnlinkFailure::SourceMissing) => Error::IoFailure(primary_failure),
            Err(UnlinkFailure::NotCommitted { phase, source }) => Error::IoFailure(format!(
                "{primary_failure}; stale recovery cursor temporary file requires later cleanup at control/{temp_name}: cleanup not committed at phase={phase:?}: {source}"
            )),
            Err(UnlinkFailure::OutcomeUnknown { phase, source }) => Error::IoFailure(format!(
                "{primary_failure}; cleanup durability is unknown for stale recovery cursor temporary file control/{temp_name}: phase={phase:?}: {source}"
            )),
        }
    }

    /// Run one bounded recovery pass.
    pub fn recover(&mut self, budget: &WorkBudget) -> RecoveryStats {
        self.recover_with_scan_budget(budget, &RecoveryScanBudget::default())
            .stats
    }

    /// Run one bounded recovery pass with explicit directory scan limits.
    pub fn recover_with_scan_budget(
        &mut self,
        budget: &WorkBudget,
        scan_budget: &RecoveryScanBudget,
    ) -> RecoveryReport {
        let mut stats = RecoveryStats::default();
        let mut scan_stats = RecoveryScanStats::default();
        if let Err(error) = scan_budget.validate() {
            stats.phase_blocked = true;
            stats.errors.push(RecoveryError {
                operation: "recovery_scan_budget".into(),
                relative_path: "/".into(),
                error: error.to_string(),
            });
            return RecoveryReport {
                stats,
                scan: scan_stats,
            };
        }
        let _recovery_lock = match self.acquire_recovery_lock() {
            Ok(lock) => lock,
            Err(error) => {
                stats.errors.push(RecoveryError {
                    operation: "recovery_lock".into(),
                    relative_path: "control/recovery.lock".into(),
                    error: error.to_string(),
                });
                return RecoveryReport {
                    stats,
                    scan: scan_stats,
                };
            }
        };
        self.recovery_cursor = match load_recovery_cursor(self.root_fd(), self.format.queue_id()) {
            Ok(cursor) => cursor,
            Err(error) => {
                stats.errors.push(RecoveryError {
                    operation: "recovery_cursor_reload".into(),
                    relative_path: format!("control/{RECOVERY_CURSOR_FILE}"),
                    error: error.to_string(),
                });
                return RecoveryReport {
                    stats,
                    scan: scan_stats,
                };
            }
        };
        let boottime_now = match fs::clock_boottime_ns() {
            Ok(t) => t,
            Err(e) => {
                stats.errors.push(RecoveryError {
                    operation: "clock_boottime".into(),
                    relative_path: "/".into(),
                    error: e.to_string(),
                });
                return RecoveryReport {
                    stats,
                    scan: scan_stats,
                };
            }
        };
        // Use checked wall floor. If unavailable, record error and
        // skip wall-sensitive phases (delayed promotion, receipt retention).
        let wall_floor = self.stabilized_wall_floor();
        if let Err(error) = &wall_floor {
            stats.errors.push(RecoveryError {
                operation: "wall_floor".into(),
                relative_path: "/".into(),
                error: format!(
                    "wall floor unavailable, skipping wall-sensitive recovery actions: {error}"
                ),
            });
        }
        let wall_floor = wall_floor.ok();
        // Use CLOCK_MONOTONIC for budget enforcement
        let start_mono = match fs::clock_monotonic_ns() {
            Ok(t) => t,
            Err(e) => {
                stats.errors.push(RecoveryError {
                    operation: "clock_monotonic".into(),
                    relative_path: "/".into(),
                    error: e.to_string(),
                });
                return RecoveryReport {
                    stats,
                    scan: scan_stats,
                };
            }
        };
        let deadline_mono =
            start_mono.saturating_add(budget.max_duration_ms.saturating_mul(1_000_000));
        let mut scan = RecoveryScanContext {
            budget: scan_budget,
            stats: &mut scan_stats,
        };

        loop {
            if !Self::has_recovery_budget(&stats) {
                break;
            }
            let phase = self.recovery_cursor.phase;
            let next_phase = match phase {
                RecoveryPhase::ReapLeases => {
                    self.reap_expired_leases(
                        boottime_now,
                        wall_floor,
                        budget,
                        &mut scan,
                        &mut stats,
                        deadline_mono,
                    );
                    RecoveryPhase::PromoteDelayed
                }
                RecoveryPhase::PromoteDelayed => {
                    if let Some(wall_floor) = wall_floor {
                        self.promote_delayed(
                            wall_floor,
                            budget,
                            &mut scan,
                            &mut stats,
                            deadline_mono,
                        );
                    }
                    RecoveryPhase::CleanupTemp
                }
                RecoveryPhase::CleanupTemp => {
                    self.cleanup_temp_files(
                        boottime_now,
                        budget,
                        &mut scan,
                        &mut stats,
                        deadline_mono,
                    );
                    RecoveryPhase::CompactReceipts
                }
                RecoveryPhase::CompactReceipts => {
                    self.compact_receipts_with_scan_budget(
                        budget,
                        &mut scan,
                        &mut stats,
                        deadline_mono,
                    );
                    RecoveryPhase::DeleteReceipts
                }
                RecoveryPhase::DeleteReceipts => {
                    if let Some(wall_floor) = wall_floor {
                        self.delete_expired_receipts(
                            wall_floor,
                            self.options.receipt_retention_ns,
                            budget,
                            &mut scan,
                            &mut stats,
                            deadline_mono,
                        );
                    }
                    RecoveryPhase::ReapLeases
                }
            };
            if Self::has_recovery_budget(&stats) {
                self.recovery_cursor.phase = next_phase;
            }
            if Self::work_budget_exhausted(&mut stats, budget, deadline_mono) {
                stats.budget_exhausted = true;
            }
            if phase == RecoveryPhase::DeleteReceipts {
                break;
            }
        }

        if let Err(error) = self.persist_recovery_cursor() {
            stats.errors.push(RecoveryError {
                operation: "recovery_cursor_persist".into(),
                relative_path: format!("control/{RECOVERY_CURSOR_FILE}"),
                error: error.to_string(),
            });
        }

        RecoveryReport {
            stats,
            scan: scan_stats,
        }
    }

    /// Quarantine an object during recovery.
    fn quarantine_recovery_object(
        &self,
        candidate: RecoveryQuarantineCandidate<'_>,
        stats: &mut RecoveryStats,
        budget: &WorkBudget,
    ) -> bool {
        self.quarantine_recovery_object_with_ids(candidate, stats, budget, fs::random_128bit)
    }

    fn quarantine_recovery_object_with_ids<F>(
        &self,
        candidate: RecoveryQuarantineCandidate<'_>,
        stats: &mut RecoveryStats,
        budget: &WorkBudget,
        next_id: F,
    ) -> bool
    where
        F: FnMut() -> io::Result<[u8; 16]>,
    {
        let remaining_attempts = budget
            .max_operations
            .saturating_sub(stats.operations_attempted);
        if remaining_attempts == 0 {
            stats.budget_exhausted = true;
            return false;
        }
        let result = self.publish_quarantine_object_with_ids(
            candidate.source_directory_fd,
            candidate.filename,
            candidate.reason,
            usize::try_from(remaining_attempts).unwrap_or(usize::MAX),
            next_id,
        );
        let attempts_consumed = match &result {
            Ok(publication) => publication.attempts_consumed,
            Err(error) => error.attempts_consumed(),
        };
        stats.operations_attempted = stats
            .operations_attempted
            .saturating_add(u32::try_from(attempts_consumed).unwrap_or(u32::MAX));
        match result {
            Ok(publication) => {
                stats.quarantined.push(RecoveryQuarantine {
                    relative_path: candidate.relative_path.to_string(),
                    quarantine_id: publication.quarantine_id,
                    quarantine_name: publication.quarantine_name,
                });
                true
            }
            Err(crate::quarantine::QuarantinePublishFailure::BudgetExhausted { .. }) => {
                Self::record_error(
                    stats,
                    "quarantine_budget_exhausted",
                    candidate.relative_path,
                    "quarantine collision retries exhausted the remaining operation budget",
                );
                stats.budget_exhausted = true;
                false
            }
            Err(error) => {
                Self::record_error(
                    stats,
                    "quarantine",
                    candidate.relative_path,
                    &error.to_string(),
                );
                true
            }
        }
    }

    /// Check if the monotonic deadline has been exceeded.
    fn budget_time_exceeded(deadline_mono: u64) -> io::Result<bool> {
        fs::clock_monotonic_ns().map(|now| now >= deadline_mono)
    }

    /// Check whether classification or mutation work must stop.
    ///
    /// Directory enumeration limits are enforced before starting the next
    /// read. Reaching a scan limit must not discard entries already returned.
    fn work_budget_exhausted(
        stats: &mut RecoveryStats,
        budget: &WorkBudget,
        deadline_mono: u64,
    ) -> bool {
        if stats.operations_attempted >= budget.max_operations {
            return true;
        }
        match Self::budget_time_exceeded(deadline_mono) {
            Ok(exceeded) => exceeded,
            Err(error) => {
                Self::block_phase(
                    stats,
                    "clock_monotonic",
                    "/",
                    &format!("recovery budget clock unavailable: {error}"),
                );
                true
            }
        }
    }

    fn has_recovery_budget(stats: &RecoveryStats) -> bool {
        !stats.budget_exhausted
    }

    fn record_error(stats: &mut RecoveryStats, op: &str, path: &str, err: &str) {
        stats.errors.push(RecoveryError {
            operation: op.into(),
            relative_path: path.into(),
            error: err.into(),
        });
    }

    fn record_move_failure(
        stats: &mut RecoveryStats,
        operation: &str,
        path: &str,
        failure: MoveFailure,
    ) {
        let (category, detail) = match failure {
            MoveFailure::NotCommitted { phase, source } => {
                ("not_committed", format!("phase={phase:?}: {source}"))
            }
            MoveFailure::OutcomeUnknown { phase, source } => {
                ("outcome_unknown", format!("phase={phase:?}: {source}"))
            }
            MoveFailure::AlreadyExists => (
                "collision",
                "phase=Rename: destination already exists".into(),
            ),
            MoveFailure::SourceMissing => {
                ("source_missing", "phase=Rename: source is missing".into())
            }
        };
        Self::record_error(stats, &format!("{operation}_{category}"), path, &detail);
    }

    fn record_unlink_failure(
        stats: &mut RecoveryStats,
        operation: &str,
        path: &str,
        failure: UnlinkFailure,
    ) {
        let (category, detail) = match failure {
            UnlinkFailure::NotCommitted { phase, source } => {
                ("not_committed", format!("phase={phase:?}: {source}"))
            }
            UnlinkFailure::OutcomeUnknown { phase, source } => {
                ("outcome_unknown", format!("phase={phase:?}: {source}"))
            }
            UnlinkFailure::SourceMissing => {
                ("source_missing", "phase=Unlink: source is missing".into())
            }
        };
        Self::record_error(stats, &format!("{operation}_{category}"), path, &detail);
    }

    fn record_remove_directory_failure(
        stats: &mut RecoveryStats,
        operation: &str,
        path: &str,
        failure: RemoveDirectoryFailure,
    ) {
        let (category, detail) = match failure {
            RemoveDirectoryFailure::NotCommitted { phase, source } => {
                ("not_committed", format!("phase={phase:?}: {source}"))
            }
            RemoveDirectoryFailure::OutcomeUnknown { phase, source } => {
                ("outcome_unknown", format!("phase={phase:?}: {source}"))
            }
            RemoveDirectoryFailure::SourceMissing => (
                "source_missing",
                "phase=Remove: directory is missing".into(),
            ),
            RemoveDirectoryFailure::NotEmpty => {
                ("not_empty", "phase=Remove: directory is not empty".into())
            }
        };
        Self::record_error(stats, &format!("{operation}_{category}"), path, &detail);
    }

    fn record_replace_failure(
        stats: &mut RecoveryStats,
        operation: &str,
        path: &str,
        failure: ReplaceFailure,
    ) {
        let (category, detail) = match failure {
            ReplaceFailure::NotCommitted { phase, source } => {
                ("not_committed", format!("phase={phase:?}: {source}"))
            }
            ReplaceFailure::OutcomeUnknown { phase, source } => {
                ("outcome_unknown", format!("phase={phase:?}: {source}"))
            }
            ReplaceFailure::SourceMissing => {
                ("source_missing", "phase=Rename: source is missing".into())
            }
            ReplaceFailure::DestinationChanged => (
                "destination_changed",
                "phase=DestinationIdentity: destination identity changed".into(),
            ),
        };
        Self::record_error(stats, &format!("{operation}_{category}"), path, &detail);
    }

    fn cleanup_compaction_temp(
        stats: &mut RecoveryStats,
        directory_fd: BorrowedFd<'_>,
        name: &str,
        relative_path: &str,
    ) {
        match unlink_verified(directory_fd, name) {
            Ok(()) | Err(UnlinkFailure::SourceMissing) => {}
            Err(failure) => Self::record_unlink_failure(
                stats,
                "receipt_compact_temp_cleanup",
                relative_path,
                failure,
            ),
        }
    }

    fn block_phase(stats: &mut RecoveryStats, op: &str, path: &str, err: &str) {
        Self::record_error(stats, op, path, err);
        stats.phase_blocked = true;
    }

    fn record_directory_error(
        stats: &mut RecoveryStats,
        op: &str,
        path: &str,
        error: &RecoveryDirectoryError,
    ) -> bool {
        match error {
            RecoveryDirectoryError::BudgetExhausted => {
                stats.budget_exhausted = true;
                true
            }
            RecoveryDirectoryError::Clock(error) => {
                Self::block_phase(
                    stats,
                    "clock_monotonic",
                    path,
                    &format!("directory budget clock unavailable during {op}: {error}"),
                );
                stats.budget_exhausted = true;
                true
            }
            RecoveryDirectoryError::Io(error) => {
                Self::block_phase(stats, op, path, &error.to_string());
                false
            }
        }
    }

    fn remember_hierarchy_retry(
        &mut self,
        phase: RecoveryPhase,
        kind: RecoveryHierarchyRetryKind,
        components: &[&[u8]],
    ) -> RememberHierarchyRetry {
        let Some(components) = components
            .iter()
            .map(|component| std::str::from_utf8(component).ok().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
        else {
            return RememberHierarchyRetry::Invalid;
        };
        let retry = RecoveryHierarchyRetry {
            phase,
            kind,
            components,
        };
        match self.recovery_cursor.hierarchy_retries.binary_search(&retry) {
            Ok(_) => RememberHierarchyRetry::Exact,
            Err(index)
                if self.recovery_cursor.hierarchy_retries.len()
                    < MAX_RECOVERY_HIERARCHY_RETRIES =>
            {
                self.recovery_cursor.hierarchy_retries.insert(index, retry);
                RememberHierarchyRetry::Exact
            }
            Err(_) => {
                if let Err(index) = self
                    .recovery_cursor
                    .hierarchy_retry_overflow
                    .binary_search(&phase)
                {
                    self.recovery_cursor
                        .hierarchy_retry_overflow
                        .insert(index, phase);
                }
                RememberHierarchyRetry::Overflow
            }
        }
    }

    fn remember_hierarchy_retry_or_block(
        &mut self,
        phase: RecoveryPhase,
        kind: RecoveryHierarchyRetryKind,
        components: &[&[u8]],
        stats: &mut RecoveryStats,
        path: &str,
    ) -> bool {
        match self.remember_hierarchy_retry(phase, kind, components) {
            RememberHierarchyRetry::Exact => true,
            RememberHierarchyRetry::Overflow => {
                Self::block_phase(
                    stats,
                    "hierarchy_retry_overflow",
                    path,
                    "recovery hierarchy retry ledger is full; phase will be fully rescanned",
                );
                true
            }
            RememberHierarchyRetry::Invalid => {
                Self::block_phase(
                    stats,
                    "hierarchy_retry_invalid",
                    path,
                    "recovery hierarchy retry path is not canonical UTF-8",
                );
                false
            }
        }
    }

    fn clear_phase_cursor(&mut self, phase: RecoveryPhase) {
        match phase {
            RecoveryPhase::ReapLeases => self.recovery_cursor.reap_leases = None,
            RecoveryPhase::PromoteDelayed => self.recovery_cursor.promote_delayed = None,
            RecoveryPhase::CleanupTemp => self.recovery_cursor.cleanup_temp = None,
            RecoveryPhase::CompactReceipts => self.recovery_cursor.compact_receipts = None,
            RecoveryPhase::DeleteReceipts => self.recovery_cursor.delete_receipts = None,
        }
    }

    fn prepare_hierarchy_retry_phase(
        &mut self,
        phase: RecoveryPhase,
    ) -> Option<RecoveryHierarchyRetry> {
        if let Ok(index) = self
            .recovery_cursor
            .hierarchy_retry_overflow
            .binary_search(&phase)
        {
            self.recovery_cursor.hierarchy_retry_overflow.remove(index);
            self.clear_phase_cursor(phase);
        }
        self.next_hierarchy_retry(phase)
    }

    fn next_hierarchy_retry(&self, phase: RecoveryPhase) -> Option<RecoveryHierarchyRetry> {
        let retries = self
            .recovery_cursor
            .hierarchy_retries
            .iter()
            .filter(|retry| retry.phase == phase)
            .collect::<Vec<_>>();
        let first = (*retries.first()?).clone();
        let Some(frontier) = self
            .recovery_cursor
            .hierarchy_retry_frontiers
            .iter()
            .find(|frontier| frontier.phase == phase)
        else {
            return Some(first);
        };
        retries
            .into_iter()
            .find(|retry| *retry > frontier)
            .cloned()
            .or(Some(first))
    }

    fn advance_hierarchy_retry_frontier(&mut self, retry: RecoveryHierarchyRetry) {
        match self
            .recovery_cursor
            .hierarchy_retry_frontiers
            .binary_search_by_key(&retry.phase, |frontier| frontier.phase)
        {
            Ok(index) => self.recovery_cursor.hierarchy_retry_frontiers[index] = retry,
            Err(index) => self
                .recovery_cursor
                .hierarchy_retry_frontiers
                .insert(index, retry),
        }
    }

    fn retry_one_hierarchy_directory(
        &mut self,
        phase: RecoveryPhase,
        retry: Option<RecoveryHierarchyRetry>,
        phase_root_fd: BorrowedFd<'_>,
        scan: &mut RecoveryScanContext<'_>,
        stats: &mut RecoveryStats,
        deadline_mono: u64,
    ) -> bool {
        let Some(retry) = retry else {
            self.recovery_cursor
                .hierarchy_retry_frontiers
                .retain(|frontier| frontier.phase != phase);
            return false;
        };
        match Self::budget_time_exceeded(deadline_mono) {
            Ok(true) => {
                stats.budget_exhausted = true;
                return true;
            }
            Ok(false) => {}
            Err(error) => {
                Self::block_phase(
                    stats,
                    "clock_monotonic",
                    "/",
                    &format!("recovery retry budget clock unavailable: {error}"),
                );
                stats.budget_exhausted = true;
                return true;
            }
        }
        let mut current = None::<OwnedFd>;
        let mut failure = None;
        let mut absent = false;
        for component in &retry.components {
            match Self::budget_time_exceeded(deadline_mono) {
                Ok(true) => {
                    stats.budget_exhausted = true;
                    return true;
                }
                Ok(false) => {}
                Err(error) => {
                    Self::block_phase(
                        stats,
                        "clock_monotonic",
                        "/",
                        &format!("recovery retry budget clock unavailable: {error}"),
                    );
                    stats.budget_exhausted = true;
                    return true;
                }
            }
            let parent_fd = current
                .as_ref()
                .map_or(phase_root_fd, |directory| directory.as_fd());
            match fs::open_directory(parent_fd, component) {
                Ok(directory) => current = Some(directory),
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                    absent = true;
                    break;
                }
                Err(error) => {
                    failure = Some(error);
                    break;
                }
            }
        }
        if let Some(error) = failure {
            stats.scan_skips += 1;
            Self::block_phase(
                stats,
                "hierarchy_retry_open",
                &retry
                    .components
                    .iter()
                    .map(|component| steadq_names::hex_encode(component.as_bytes()))
                    .collect::<Vec<_>>()
                    .join("/"),
                &error.to_string(),
            );
            self.advance_hierarchy_retry_frontier(retry);
            return false;
        }

        if !absent && retry.kind == RecoveryHierarchyRetryKind::Enumerate {
            let directory = current
                .as_ref()
                .expect("validated retry paths contain at least one component");
            if let Err(error) =
                read_recovery_directory(directory.as_fd(), deadline_mono, scan.budget, scan.stats)
            {
                if Self::record_directory_error(
                    stats,
                    "hierarchy_retry_read",
                    &retry
                        .components
                        .iter()
                        .map(|component| steadq_names::hex_encode(component.as_bytes()))
                        .collect::<Vec<_>>()
                        .join("/"),
                    &error,
                ) {
                    return true;
                }
                stats.scan_skips += 1;
                self.advance_hierarchy_retry_frontier(retry);
                return false;
            }
        }

        self.recovery_cursor
            .hierarchy_retries
            .retain(|candidate| candidate != &retry);
        self.clear_phase_cursor(phase);
        if self
            .recovery_cursor
            .hierarchy_retries
            .iter()
            .any(|candidate| candidate.phase == phase)
        {
            self.advance_hierarchy_retry_frontier(retry);
        } else {
            self.recovery_cursor
                .hierarchy_retry_frontiers
                .retain(|frontier| frontier.phase != phase);
        }
        false
    }
}

mod phases;

#[cfg(test)]
mod tests;
