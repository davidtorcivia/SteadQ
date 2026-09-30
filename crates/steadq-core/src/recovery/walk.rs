// Shared steps of the resumable recovery directory walk.
use super::*;

/// Outcome of descending into one hierarchy directory.
pub(super) enum Descend {
    /// The directory opened and was enumerated in full, sorted.
    Entries(OwnedFd, Vec<fs::DirEntryName>),
    /// The directory failed and is remembered for a hierarchy retry.
    Skip,
    /// The pass must stop.
    Stop,
}

/// One directory below a phase root.
pub(super) struct Level<'a> {
    pub(super) phase: RecoveryPhase,
    /// Name of the directory inside its parent.
    pub(super) name: &'a str,
    /// Raw names from the phase root down to and including this directory.
    pub(super) components: &'a [&'a [u8]],
    pub(super) open_operation: &'a str,
    pub(super) read_operation: &'a str,
    /// Path recorded with read errors and hierarchy retry blocks.
    pub(super) path: &'a str,
    /// Path recorded with the open error.
    pub(super) open_error_path: &'a str,
}

/// Result of removing a directory whose observed children are all gone.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum Prune {
    Removed,
    Missing,
    /// Not empty, or the failure was recorded.
    Kept,
    /// The work budget is exhausted.
    Stop,
}

/// Whether a directory sorts before the saved cursor under the saved parents.
pub(super) fn directory_before_cursor<const N: usize>(
    cursor: Option<[&[u8]; N]>,
    parents: &[&[u8]],
    name: &[u8],
) -> bool {
    cursor.is_some_and(|cursor| cursor[..parents.len()] == *parents && name < cursor[parents.len()])
}

fn ascii_directory_name<'n>(
    stats: &mut RecoveryStats,
    operation: &str,
    entry: &'n fs::DirEntryName,
    kind: &str,
) -> Option<&'n str> {
    let name = entry.as_ascii_str();
    if name.is_none() {
        Queue::record_error(
            stats,
            operation,
            &raw_name_for_error(entry),
            &format!("{kind} directory name is not ASCII"),
        );
    }
    name
}

fn record_noncanonical(stats: &mut RecoveryStats, operation: &str, name: &str, kind: &str) {
    Queue::record_error(
        stats,
        operation,
        name,
        &format!("{kind} directory name is not canonical"),
    );
}

/// Canonical boot directory name, or None after recording why not.
pub(super) fn boot_directory_name<'n>(
    stats: &mut RecoveryStats,
    operation: &str,
    entry: &'n fs::DirEntryName,
) -> Option<&'n str> {
    let name = ascii_directory_name(stats, operation, entry, "boot")?;
    if steadq_names::boot_id_bytes(name).is_none() {
        record_noncanonical(stats, operation, name, "boot");
        return None;
    }
    Some(name)
}

/// Canonical bucket directory name and number, or None after recording why not.
pub(super) fn bucket_directory_name<'n>(
    stats: &mut RecoveryStats,
    operation: &str,
    entry: &'n fs::DirEntryName,
) -> Option<(&'n str, u64)> {
    let name = ascii_directory_name(stats, operation, entry, "bucket")?;
    let Some(bucket) = steadq_names::bucket_from_hex(name) else {
        record_noncanonical(stats, operation, name, "bucket");
        return None;
    };
    Some((name, bucket))
}

/// In-range shard directory name and number, or None after recording why not.
pub(super) fn shard_directory_name<'n>(
    stats: &mut RecoveryStats,
    operation: &str,
    entry: &'n fs::DirEntryName,
    shard_count: u32,
) -> Option<(&'n str, u32)> {
    let name = ascii_directory_name(stats, operation, entry, "shard")?;
    let Some(shard) = steadq_names::shard_from_hex(name) else {
        record_noncanonical(stats, operation, name, "shard");
        return None;
    };
    if shard >= shard_count {
        Queue::record_error(
            stats,
            operation,
            name,
            "shard directory is outside the queue shard range",
        );
        return None;
    }
    Some((name, shard))
}

impl Queue {
    /// Open and enumerate one hierarchy directory. An open or read failure
    /// counts a scan skip, blocks the phase, and is remembered for a
    /// hierarchy retry so later siblings still make progress.
    pub(super) fn descend_level(
        &mut self,
        parent_fd: BorrowedFd<'_>,
        level: &Level<'_>,
        scan: &mut RecoveryScanContext<'_>,
        stats: &mut RecoveryStats,
        deadline_mono: u64,
    ) -> Descend {
        let fd = match fs::open_directory(parent_fd, level.name) {
            Ok(fd) => fd,
            Err(error) => {
                stats.scan_skips += 1;
                Self::block_phase(
                    stats,
                    level.open_operation,
                    level.open_error_path,
                    &error.to_string(),
                );
                return self.remember_level_retry(level, RecoveryHierarchyRetryKind::Open, stats);
            }
        };
        match read_recovery_directory(fd.as_fd(), deadline_mono, scan.budget, scan.stats) {
            Ok(mut entries) => {
                entries.sort();
                Descend::Entries(fd, entries)
            }
            Err(error) => {
                stats.scan_skips += 1;
                if Self::record_directory_error(stats, level.read_operation, level.path, &error) {
                    return Descend::Stop;
                }
                self.remember_level_retry(level, RecoveryHierarchyRetryKind::Enumerate, stats)
            }
        }
    }

    fn remember_level_retry(
        &mut self,
        level: &Level<'_>,
        kind: RecoveryHierarchyRetryKind,
        stats: &mut RecoveryStats,
    ) -> Descend {
        if self.remember_hierarchy_retry_or_block(
            level.phase,
            kind,
            level.components,
            stats,
            level.path,
        ) {
            Descend::Skip
        } else {
            Descend::Stop
        }
    }

    /// Remove an empty hierarchy directory once the work budget allows it.
    pub(super) fn prune_empty_directory(
        parent_fd: BorrowedFd<'_>,
        name: &str,
        operation: &str,
        path: &str,
        budget: &WorkBudget,
        stats: &mut RecoveryStats,
        deadline_mono: u64,
    ) -> Prune {
        if Self::work_budget_exhausted(stats, budget, deadline_mono) {
            stats.budget_exhausted = true;
            return Prune::Stop;
        }
        stats.operations_attempted += 1;
        match remove_empty_directory_verified(parent_fd, name) {
            Ok(()) => Prune::Removed,
            Err(RemoveDirectoryFailure::SourceMissing) => Prune::Missing,
            Err(RemoveDirectoryFailure::NotEmpty) => Prune::Kept,
            Err(failure) => {
                Self::record_remove_directory_failure(stats, operation, path, failure);
                Prune::Kept
            }
        }
    }
}
