// Phase-aware durable move engine: single source for rename+fsync with actor attribution.
//
// Every state transition linearizes via RENAME_NOREPLACE and then syncs each
// distinct affected directory. Errors before the rename are retryable
// (NotCommitted); later errors are OutcomeUnknown.

use std::collections::HashMap;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use steadq_fs_linux as fs;

use crate::errors::Error;

/// Explicit dirty-directory tracking. Records the exact directory FDs that
/// need durability and deduplicates by device plus inode. Replaces the
/// old TLS deferred_dir_sync mechanism which globally suppressed unrelated
/// durability fsyncs.
#[derive(Debug, Default)]
pub struct DirtySet {
    dirs: HashMap<(u64, u64), OwnedFd>,
}

impl DirtySet {
    pub fn new() -> Self {
        Self {
            dirs: HashMap::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.dirs.is_empty()
    }

    pub fn len(&self) -> usize {
        self.dirs.len()
    }

    pub fn clear(&mut self) {
        self.dirs.clear();
    }

    pub fn extend(&mut self, other: Self) {
        for (k, v) in other.dirs {
            self.dirs.entry(k).or_insert(v);
        }
    }

    /// Record a directory that needs fsync. Deduplicates by device and inode.
    pub fn record(&mut self, fd: BorrowedFd) -> io::Result<()> {
        self.record_with(fd, |fd| {
            fd.try_clone_to_owned()
                .map_err(|error| io::Error::other(error.to_string()))
        })
    }

    pub(super) fn record_with(
        &mut self,
        fd: BorrowedFd,
        clone_fd: impl FnOnce(BorrowedFd<'_>) -> io::Result<OwnedFd>,
    ) -> io::Result<()> {
        let stat = fs::fstat(fd)?;
        let key = (stat.st_dev as u64, stat.st_ino as u64);
        let std::collections::hash_map::Entry::Vacant(entry) = self.dirs.entry(key) else {
            return Ok(());
        };
        entry.insert(clone_fd(fd)?);
        Ok(())
    }

    /// Fsync every recorded directory exactly once. Returns the first error
    /// if any, after attempting all.
    pub fn sync_all(&self) -> io::Result<()> {
        let mut first_err: Option<io::Error> = None;
        for fd in self.dirs.values() {
            if let Err(error) = fs::fsync_dir_fd(fd.as_fd()) {
                if first_err.is_none() {
                    first_err = Some(error);
                }
            }
        }
        if let Some(e) = first_err {
            Err(e)
        } else {
            Ok(())
        }
    }
}

/// Phase where the move failed. Determines whether the effect is known durable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MovePhase {
    EnsureDest,
    PreRename,
    Rename,
    DestinationIdentity,
    PostLinearization,
    DestFsync,
    SourceFsync,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MoveIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Copy)]
enum DirectoryDurability {
    Strict,
    Deferred,
}

#[derive(Clone, Copy)]
struct MoveOptions {
    source_identity: Option<MoveIdentity>,
    directory_durability: DirectoryDurability,
}

impl MoveIdentity {
    pub fn new(device: u64, inode: u64) -> Self {
        Self { device, inode }
    }

    fn matches(self, stat: &libc::stat) -> bool {
        stat.st_mode & libc::S_IFMT == libc::S_IFREG
            && stat.st_nlink == 1
            && stat.st_size >= 0
            && stat.st_dev == self.device
            && stat.st_ino == self.inode
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MovedObject {
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) size: u64,
}

impl MovedObject {
    pub fn device(self) -> u64 {
        self.device
    }

    pub fn inode(self) -> u64 {
        self.inode
    }

    pub fn size(self) -> u64 {
        self.size
    }
}

#[derive(Debug)]
pub enum MoveFailure {
    /// The rename did not happen. The destination still needs provisioning
    /// or the source vanished before linearizing.
    NotCommitted {
        phase: MovePhase,
        source: std::io::Error,
    },
    /// The rename happened but the durability barrier failed.
    /// The queue must be poisoned and the caller must surface OutcomeUnknown.
    OutcomeUnknown {
        phase: MovePhase,
        source: std::io::Error,
    },
    /// The rename failed with EEXIST because the destination already exists.
    /// For ack-style exact-source moves this is LeaseLost under verified handles;
    /// for publication it is a retriable not-committed without poison.
    AlreadyExists,
    /// The exact source was missing at rename time.
    SourceMissing,
}

#[derive(Debug)]
pub(super) enum MoveFailureWith<E> {
    NotCommitted { phase: MovePhase, source: E },
    OutcomeUnknown { phase: MovePhase, source: E },
    AlreadyExists,
    SourceMissing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TmpfilePublishPhase {
    SourceIdentity,
    FileFsync,
    Link,
    DestinationFsync,
}

#[derive(Debug)]
pub(super) enum TmpfilePublishOutcome {
    Published(fs::PublicationMode),
    Unsupported,
}

#[derive(Debug)]
pub(super) enum TmpfilePublishFailure {
    NotCommitted {
        phase: TmpfilePublishPhase,
        source: std::io::Error,
    },
    OutcomeUnknown {
        phase: TmpfilePublishPhase,
        source: std::io::Error,
    },
    AlreadyExists,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnlinkPhase {
    Unlink,
    DirectoryFsync,
}

#[derive(Debug)]
pub enum UnlinkFailure {
    NotCommitted {
        phase: UnlinkPhase,
        source: std::io::Error,
    },
    OutcomeUnknown {
        phase: UnlinkPhase,
        source: std::io::Error,
    },
    SourceMissing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoveDirectoryPhase {
    Remove,
    ParentFsync,
}

#[derive(Debug)]
pub enum RemoveDirectoryFailure {
    NotCommitted {
        phase: RemoveDirectoryPhase,
        source: std::io::Error,
    },
    OutcomeUnknown {
        phase: RemoveDirectoryPhase,
        source: std::io::Error,
    },
    SourceMissing,
    NotEmpty,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplacePhase {
    DestinationIdentity,
    Rename,
    DirectoryIdentity,
    DestinationFsync,
    SourceFsync,
}

#[derive(Debug)]
pub enum ReplaceFailure {
    NotCommitted {
        phase: ReplacePhase,
        source: std::io::Error,
    },
    OutcomeUnknown {
        phase: ReplacePhase,
        source: std::io::Error,
    },
    SourceMissing,
    DestinationChanged,
}

impl ReplaceFailure {
    pub fn phase(&self) -> Option<ReplacePhase> {
        match self {
            Self::NotCommitted { phase, .. } | Self::OutcomeUnknown { phase, .. } => Some(*phase),
            Self::SourceMissing | Self::DestinationChanged => None,
        }
    }

    pub fn is_outcome_unknown(&self) -> bool {
        matches!(self, Self::OutcomeUnknown { .. })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplaceIdentity {
    device: u64,
    inode: u64,
}

impl ReplaceIdentity {
    pub fn new(device: u64, inode: u64) -> Self {
        Self { device, inode }
    }

    fn matches(self, stat: &libc::stat) -> bool {
        stat.st_dev == self.device && stat.st_ino == self.inode
    }
}

impl UnlinkFailure {
    pub fn phase(&self) -> Option<UnlinkPhase> {
        match self {
            Self::NotCommitted { phase, .. } | Self::OutcomeUnknown { phase, .. } => Some(*phase),
            Self::SourceMissing => None,
        }
    }

    pub fn is_outcome_unknown(&self) -> bool {
        matches!(self, Self::OutcomeUnknown { .. })
    }
}

impl RemoveDirectoryFailure {
    pub fn phase(&self) -> Option<RemoveDirectoryPhase> {
        match self {
            Self::NotCommitted { phase, .. } | Self::OutcomeUnknown { phase, .. } => Some(*phase),
            Self::SourceMissing | Self::NotEmpty => None,
        }
    }

    pub fn is_outcome_unknown(&self) -> bool {
        matches!(self, Self::OutcomeUnknown { .. })
    }
}

impl MoveFailure {
    pub fn is_outcome_unknown(&self) -> bool {
        matches!(self, Self::OutcomeUnknown { .. })
    }
    pub fn is_not_committed(&self) -> bool {
        matches!(self, Self::NotCommitted { .. })
    }
    pub fn phase(&self) -> Option<MovePhase> {
        match self {
            Self::NotCommitted { phase, .. } | Self::OutcomeUnknown { phase, .. } => Some(*phase),
            _ => None,
        }
    }
}

impl<E> MoveFailureWith<E> {
    pub(super) fn is_outcome_unknown(&self) -> bool {
        matches!(self, Self::OutcomeUnknown { .. })
    }

    #[cfg(test)]
    fn phase(&self) -> Option<MovePhase> {
        match self {
            Self::NotCommitted { phase, .. } | Self::OutcomeUnknown { phase, .. } => Some(*phase),
            Self::AlreadyExists | Self::SourceMissing => None,
        }
    }
}

impl TmpfilePublishFailure {
    #[cfg(test)]
    fn is_outcome_unknown(&self) -> bool {
        matches!(self, Self::OutcomeUnknown { .. })
    }

    #[cfg(test)]
    fn phase(&self) -> Option<TmpfilePublishPhase> {
        match self {
            Self::NotCommitted { phase, .. } | Self::OutcomeUnknown { phase, .. } => Some(*phase),
            Self::AlreadyExists => None,
        }
    }
}

impl From<MoveFailureWith<std::io::Error>> for MoveFailure {
    fn from(failure: MoveFailureWith<std::io::Error>) -> Self {
        match failure {
            MoveFailureWith::NotCommitted { phase, source } => Self::NotCommitted { phase, source },
            MoveFailureWith::OutcomeUnknown { phase, source } => {
                Self::OutcomeUnknown { phase, source }
            }
            MoveFailureWith::AlreadyExists => Self::AlreadyExists,
            MoveFailureWith::SourceMissing => Self::SourceMissing,
        }
    }
}

/// Durable move via RENAME_NOREPLACE with phase-aware error classification.
/// The caller provides already-opened dir fds for src and dest to avoid TOCTOU.
/// On success both dirs are fsynced before returning.
pub fn is_already_exists_io_kind(kind: std::io::ErrorKind) -> bool {
    kind == std::io::ErrorKind::AlreadyExists
}
pub fn is_not_found_io_kind(kind: std::io::ErrorKind) -> bool {
    kind == std::io::ErrorKind::NotFound
}

pub fn move_verified_noreplace(
    src_dir_fd: BorrowedFd<'_>,
    src_name: &str,
    dest_dir_fd: BorrowedFd<'_>,
    dest_name: &str,
) -> Result<(), MoveFailure> {
    move_noreplace(
        src_dir_fd,
        src_name,
        dest_dir_fd,
        dest_name,
        MoveOptions {
            source_identity: None,
            directory_durability: DirectoryDurability::Strict,
        },
        |error| error,
        |_| Ok(()),
    )
    .map_err(MoveFailure::from)
}

pub fn move_witnessed_noreplace(
    src_dir_fd: BorrowedFd<'_>,
    src_name: &str,
    dest_dir_fd: BorrowedFd<'_>,
    dest_name: &str,
    source_identity: MoveIdentity,
) -> Result<(), MoveFailure> {
    move_witnessed_noreplace_with(
        src_dir_fd,
        src_name,
        dest_dir_fd,
        dest_name,
        source_identity,
        |_| Ok(()),
    )
    .map(|_| ())
}

pub fn move_witnessed_noreplace_with<T>(
    src_dir_fd: BorrowedFd<'_>,
    src_name: &str,
    dest_dir_fd: BorrowedFd<'_>,
    dest_name: &str,
    source_identity: MoveIdentity,
    after_linearization: impl FnOnce(MovedObject) -> Result<T, std::io::Error>,
) -> Result<(MovedObject, T), MoveFailure> {
    move_noreplace(
        src_dir_fd,
        src_name,
        dest_dir_fd,
        dest_name,
        MoveOptions {
            source_identity: Some(source_identity),
            directory_durability: DirectoryDurability::Strict,
        },
        |error| error,
        move |moved| {
            let moved = moved.expect("witnessed move authenticates its destination");
            after_linearization(moved).map(|output| (moved, output))
        },
    )
    .map_err(MoveFailure::from)
}

pub(super) fn move_witnessed_noreplace_io(
    src_dir_fd: BorrowedFd<'_>,
    src_name: &str,
    dest_dir_fd: BorrowedFd<'_>,
    dest_name: &str,
    source_identity: MoveIdentity,
) -> Result<(), MoveFailureWith<std::io::Error>> {
    move_noreplace(
        src_dir_fd,
        src_name,
        dest_dir_fd,
        dest_name,
        MoveOptions {
            source_identity: Some(source_identity),
            directory_durability: DirectoryDurability::Strict,
        },
        |error| error,
        |_| Ok(()),
    )
}

fn move_noreplace<T, E>(
    src_dir_fd: BorrowedFd<'_>,
    src_name: &str,
    dest_dir_fd: BorrowedFd<'_>,
    dest_name: &str,
    options: MoveOptions,
    map_io_error: impl Fn(std::io::Error) -> E,
    after_linearization: impl FnOnce(Option<MovedObject>) -> Result<T, E>,
) -> Result<T, MoveFailureWith<E>> {
    match fs::renameat2_noreplace(src_dir_fd, src_name, dest_dir_fd, dest_name) {
        Ok(()) => {}
        Err(e) if is_already_exists_io_kind(e.kind()) => {
            return Err(MoveFailureWith::AlreadyExists);
        }
        Err(e) if is_not_found_io_kind(e.kind()) => {
            return Err(MoveFailureWith::SourceMissing);
        }
        Err(e) => {
            return Err(MoveFailureWith::NotCommitted {
                phase: MovePhase::Rename,
                source: map_io_error(e),
            });
        }
    };

    let detect_same_directory = options.source_identity.is_some();
    let moved = if let Some(source_identity) = options.source_identity {
        match fs::fstatat(dest_dir_fd, dest_name) {
            Ok(stat) if source_identity.matches(&stat) => Some(MovedObject {
                device: stat.st_dev,
                inode: stat.st_ino,
                size: stat.st_size.max(0) as u64,
            }),
            Ok(_) => {
                return Err(MoveFailureWith::OutcomeUnknown {
                    phase: MovePhase::DestinationIdentity,
                    source: map_io_error(std::io::Error::other(
                        "destination identity changed after rename",
                    )),
                });
            }
            Err(error) => {
                return Err(MoveFailureWith::OutcomeUnknown {
                    phase: MovePhase::DestinationIdentity,
                    source: map_io_error(error),
                });
            }
        }
    } else {
        None
    };

    let output = after_linearization(moved).map_err(|source| MoveFailureWith::OutcomeUnknown {
        phase: MovePhase::PostLinearization,
        source,
    })?;

    if matches!(options.directory_durability, DirectoryDurability::Deferred) {
        return Ok(output);
    }

    if let Err(e) = fs::fsync_dir_fd(dest_dir_fd) {
        return Err(MoveFailureWith::OutcomeUnknown {
            phase: MovePhase::DestFsync,
            source: map_io_error(e),
        });
    }

    if detect_same_directory && same_directory(src_dir_fd, dest_dir_fd) {
        return Ok(output);
    }

    if let Err(e) = fs::fsync_dir_fd(src_dir_fd) {
        return Err(MoveFailureWith::OutcomeUnknown {
            phase: MovePhase::SourceFsync,
            source: map_io_error(e),
        });
    }
    Ok(output)
}

pub(super) fn is_tmpfile_open_unsupported(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EISDIR) | Some(libc::ENOENT) | Some(libc::EOPNOTSUPP)
    )
}

fn is_direct_link_unsupported(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EINVAL) | Some(libc::ENOENT) | Some(libc::EOPNOTSUPP)
    )
}

fn is_proc_link_unsupported(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EINVAL) | Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP)
    )
}

fn unnamed_file_identity(stat: &libc::stat) -> std::io::Result<MoveIdentity> {
    if stat.st_mode & libc::S_IFMT == libc::S_IFREG && stat.st_nlink == 0 && stat.st_size >= 0 {
        Ok(MoveIdentity::new(stat.st_dev, stat.st_ino))
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "temporary publication source is not an unnamed regular file",
        ))
    }
}

enum LinkStrategyAttempt {
    Published(fs::PublicationMode),
    TryNext,
    Unsupported,
}

fn try_direct_tmpfile_link(
    tmpfile_fd: BorrowedFd<'_>,
    destination_directory_fd: BorrowedFd<'_>,
    destination_name: &str,
) -> Result<LinkStrategyAttempt, TmpfilePublishFailure> {
    match fs::linkat_empty_path(tmpfile_fd, destination_directory_fd, destination_name) {
        Ok(()) => Ok(LinkStrategyAttempt::Published(
            fs::PublicationMode::DirectAtEmptyPath,
        )),
        Err(error) if is_already_exists_io_kind(error.kind()) => {
            Err(TmpfilePublishFailure::AlreadyExists)
        }
        // Both publication forms use linkat(2), so ENOSYS rules out the proc path too.
        Err(error) if error.raw_os_error() == Some(libc::ENOSYS) => {
            Ok(LinkStrategyAttempt::Unsupported)
        }
        Err(error) if is_direct_link_unsupported(&error) => Ok(LinkStrategyAttempt::TryNext),
        Err(source) => Err(TmpfilePublishFailure::NotCommitted {
            phase: TmpfilePublishPhase::Link,
            source,
        }),
    }
}

fn try_proc_tmpfile_link(
    tmpfile_fd: BorrowedFd<'_>,
    destination_directory_fd: BorrowedFd<'_>,
    destination_name: &str,
) -> Result<LinkStrategyAttempt, TmpfilePublishFailure> {
    match fs::linkat_proc_self_fd(tmpfile_fd, destination_directory_fd, destination_name) {
        Ok(()) => Ok(LinkStrategyAttempt::Published(
            fs::PublicationMode::ProcSelfFd,
        )),
        Err(error) if is_already_exists_io_kind(error.kind()) => {
            Err(TmpfilePublishFailure::AlreadyExists)
        }
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
            let destination = fs::fstat(destination_directory_fd).map_err(|source| {
                TmpfilePublishFailure::NotCommitted {
                    phase: TmpfilePublishPhase::Link,
                    source,
                }
            })?;
            if destination.st_nlink == 0 {
                return Err(TmpfilePublishFailure::NotCommitted {
                    phase: TmpfilePublishPhase::Link,
                    source: error,
                });
            }
            Ok(LinkStrategyAttempt::TryNext)
        }
        Err(error) if is_proc_link_unsupported(&error) => Ok(LinkStrategyAttempt::TryNext),
        Err(source) => Err(TmpfilePublishFailure::NotCommitted {
            phase: TmpfilePublishPhase::Link,
            source,
        }),
    }
}

fn link_tmpfile_noreplace(
    tmpfile_fd: BorrowedFd<'_>,
    destination_directory_fd: BorrowedFd<'_>,
    destination_name: &str,
    preferred: Option<fs::PublicationMode>,
) -> Result<Option<fs::PublicationMode>, TmpfilePublishFailure> {
    let proc_first = matches!(preferred, Some(fs::PublicationMode::ProcSelfFd));
    let first = if proc_first {
        try_proc_tmpfile_link(tmpfile_fd, destination_directory_fd, destination_name)?
    } else {
        try_direct_tmpfile_link(tmpfile_fd, destination_directory_fd, destination_name)?
    };
    match first {
        LinkStrategyAttempt::Published(mode) => return Ok(Some(mode)),
        LinkStrategyAttempt::Unsupported => return Ok(None),
        LinkStrategyAttempt::TryNext => {}
    }

    let second = if proc_first {
        try_direct_tmpfile_link(tmpfile_fd, destination_directory_fd, destination_name)?
    } else {
        try_proc_tmpfile_link(tmpfile_fd, destination_directory_fd, destination_name)?
    };
    match second {
        LinkStrategyAttempt::Published(mode) => Ok(Some(mode)),
        LinkStrategyAttempt::TryNext | LinkStrategyAttempt::Unsupported => Ok(None),
    }
}

fn publish_tmpfile_noreplace_impl(
    tmpfile_fd: BorrowedFd<'_>,
    destination_directory_fd: BorrowedFd<'_>,
    destination_name: &str,
    preferred: Option<fs::PublicationMode>,
    sync_destination: bool,
) -> Result<TmpfilePublishOutcome, TmpfilePublishFailure> {
    let source_stat =
        fs::fstat(tmpfile_fd).map_err(|source| TmpfilePublishFailure::NotCommitted {
            phase: TmpfilePublishPhase::SourceIdentity,
            source,
        })?;
    unnamed_file_identity(&source_stat).map_err(|source| TmpfilePublishFailure::NotCommitted {
        phase: TmpfilePublishPhase::SourceIdentity,
        source,
    })?;

    fs::fsync(tmpfile_fd).map_err(|source| TmpfilePublishFailure::NotCommitted {
        phase: TmpfilePublishPhase::FileFsync,
        source,
    })?;

    let Some(mode) = link_tmpfile_noreplace(
        tmpfile_fd,
        destination_directory_fd,
        destination_name,
        preferred,
    )?
    else {
        return Ok(TmpfilePublishOutcome::Unsupported);
    };

    // linkat publishes the held inode atomically. Reopening its name here
    // would race a consumer that immediately claims the new job.
    if sync_destination {
        fs::fsync_dir_fd(destination_directory_fd).map_err(|source| {
            TmpfilePublishFailure::OutcomeUnknown {
                phase: TmpfilePublishPhase::DestinationFsync,
                source,
            }
        })?;
    }
    Ok(TmpfilePublishOutcome::Published(mode))
}

#[cfg(test)]
pub(super) fn publish_tmpfile_noreplace(
    tmpfile_fd: BorrowedFd<'_>,
    destination_directory_fd: BorrowedFd<'_>,
    destination_name: &str,
) -> Result<TmpfilePublishOutcome, TmpfilePublishFailure> {
    publish_tmpfile_noreplace_impl(
        tmpfile_fd,
        destination_directory_fd,
        destination_name,
        None,
        true,
    )
}

pub(super) fn publish_tmpfile_noreplace_with_mode(
    tmpfile_fd: BorrowedFd<'_>,
    destination_directory_fd: BorrowedFd<'_>,
    destination_name: &str,
    preferred: Option<fs::PublicationMode>,
) -> Result<TmpfilePublishOutcome, TmpfilePublishFailure> {
    publish_tmpfile_noreplace_impl(
        tmpfile_fd,
        destination_directory_fd,
        destination_name,
        preferred,
        true,
    )
}

fn same_directory(source: BorrowedFd<'_>, destination: BorrowedFd<'_>) -> bool {
    if source.as_raw_fd() == destination.as_raw_fd() {
        return true;
    }
    match (fs::fstat(source), fs::fstat(destination)) {
        (Ok(source), Ok(destination)) => {
            source.st_dev == destination.st_dev && source.st_ino == destination.st_ino
        }
        _ => false,
    }
}

pub fn unlink_verified(directory_fd: BorrowedFd<'_>, name: &str) -> Result<(), UnlinkFailure> {
    match fs::unlinkat(directory_fd, name) {
        Ok(()) => {}
        Err(error) if is_not_found_io_kind(error.kind()) => {
            return Err(UnlinkFailure::SourceMissing);
        }
        Err(error) => {
            return Err(UnlinkFailure::NotCommitted {
                phase: UnlinkPhase::Unlink,
                source: error,
            });
        }
    }
    fs::fsync_dir_fd(directory_fd).map_err(|error| UnlinkFailure::OutcomeUnknown {
        phase: UnlinkPhase::DirectoryFsync,
        source: error,
    })
}

fn is_directory_not_empty(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::ENOTEMPTY) | Some(libc::EEXIST)
    )
}

pub fn remove_empty_directory_verified(
    parent_directory_fd: BorrowedFd<'_>,
    name: &str,
) -> Result<(), RemoveDirectoryFailure> {
    match fs::unlinkat_dir(parent_directory_fd, name) {
        Ok(()) => {}
        Err(error) if is_not_found_io_kind(error.kind()) => {
            return Err(RemoveDirectoryFailure::SourceMissing);
        }
        Err(error) if is_directory_not_empty(&error) => {
            return Err(RemoveDirectoryFailure::NotEmpty);
        }
        Err(error) => {
            return Err(RemoveDirectoryFailure::NotCommitted {
                phase: RemoveDirectoryPhase::Remove,
                source: error,
            });
        }
    }
    fs::fsync_dir_fd(parent_directory_fd).map_err(|error| RemoveDirectoryFailure::OutcomeUnknown {
        phase: RemoveDirectoryPhase::ParentFsync,
        source: error,
    })
}

/// Atomically replace an authenticated destination and durably publish the
/// replacement. The rename is the linearization point, so every later failure
/// is outcome unknown.
pub fn replace_verified(
    src_dir_fd: BorrowedFd<'_>,
    src_name: &str,
    dest_dir_fd: BorrowedFd<'_>,
    dest_name: &str,
    expected_destination: Option<ReplaceIdentity>,
) -> Result<(), ReplaceFailure> {
    if let Some(expected_destination) = expected_destination {
        let destination =
            fs::fstatat(dest_dir_fd, dest_name).map_err(|error| ReplaceFailure::NotCommitted {
                phase: ReplacePhase::DestinationIdentity,
                source: error,
            })?;
        if !expected_destination.matches(&destination) {
            return Err(ReplaceFailure::DestinationChanged);
        }
    }

    match fs::renameat(src_dir_fd, src_name, dest_dir_fd, dest_name) {
        Ok(()) => {}
        Err(error) if is_not_found_io_kind(error.kind()) => {
            return Err(ReplaceFailure::SourceMissing);
        }
        Err(error) => {
            return Err(ReplaceFailure::NotCommitted {
                phase: ReplacePhase::Rename,
                source: error,
            });
        }
    }

    if src_dir_fd.as_raw_fd() == dest_dir_fd.as_raw_fd() {
        return fs::fsync_dir_fd(dest_dir_fd).map_err(|error| ReplaceFailure::OutcomeUnknown {
            phase: ReplacePhase::DestinationFsync,
            source: error,
        });
    }

    let src_stat = fs::fstat(src_dir_fd).map_err(|error| ReplaceFailure::OutcomeUnknown {
        phase: ReplacePhase::DirectoryIdentity,
        source: error,
    })?;
    let dest_stat = fs::fstat(dest_dir_fd).map_err(|error| ReplaceFailure::OutcomeUnknown {
        phase: ReplacePhase::DirectoryIdentity,
        source: error,
    })?;
    if src_stat.st_dev == dest_stat.st_dev && src_stat.st_ino == dest_stat.st_ino {
        return fs::fsync_dir_fd(dest_dir_fd).map_err(|error| ReplaceFailure::OutcomeUnknown {
            phase: ReplacePhase::DestinationFsync,
            source: error,
        });
    }

    fs::fsync_dir_fd(dest_dir_fd).map_err(|error| ReplaceFailure::OutcomeUnknown {
        phase: ReplacePhase::DestinationFsync,
        source: error,
    })?;
    fs::fsync_dir_fd(src_dir_fd).map_err(|error| ReplaceFailure::OutcomeUnknown {
        phase: ReplacePhase::SourceFsync,
        source: error,
    })
}

/// Deferred variants: perform the linearization without dir fsyncs. The caller must record the affected directories in a DirtySet and sync them at the batch barrier. Errors after linearization are still OutcomeUnknown, but the dir fsync phase is deferred.
pub fn move_witnessed_noreplace_deferred<T>(
    src_dir_fd: BorrowedFd<'_>,
    src_name: &str,
    dest_dir_fd: BorrowedFd<'_>,
    dest_name: &str,
    source_identity: MoveIdentity,
    after_linearization: impl FnOnce(MovedObject) -> Result<T, std::io::Error>,
) -> Result<(MovedObject, T), MoveFailure> {
    move_noreplace(
        src_dir_fd,
        src_name,
        dest_dir_fd,
        dest_name,
        MoveOptions {
            source_identity: Some(source_identity),
            directory_durability: DirectoryDurability::Deferred,
        },
        |e| e,
        move |moved| {
            let moved = moved.expect("witnessed move authenticates its destination");
            after_linearization(moved).map(|output| (moved, output))
        },
    )
    .map_err(MoveFailure::from)
}

pub(super) fn publish_tmpfile_noreplace_deferred_with_mode(
    tmpfile_fd: BorrowedFd<'_>,
    destination_directory_fd: BorrowedFd<'_>,
    destination_name: &str,
    preferred: Option<fs::PublicationMode>,
) -> Result<TmpfilePublishOutcome, TmpfilePublishFailure> {
    publish_tmpfile_noreplace_impl(
        tmpfile_fd,
        destination_directory_fd,
        destination_name,
        preferred,
        false,
    )
}

/// Convert a MoveFailure into the public Error / poison decision.
/// The caller decides poison; this helper maps phases to Error variants.
pub fn map_move_failure(f: MoveFailure) -> Error {
    match f {
        MoveFailure::AlreadyExists => Error::QueueCorrupt("destination already exists".into()),
        MoveFailure::SourceMissing => Error::QueueCorrupt("source missing".into()),
        MoveFailure::NotCommitted { source, .. } => Error::from(source),
        MoveFailure::OutcomeUnknown { source, .. } => Error::from(source),
    }
}

// helpers for mutant killing
pub fn is_already_exists(f: &MoveFailure) -> bool {
    matches!(f, MoveFailure::AlreadyExists)
}
pub fn is_source_missing(f: &MoveFailure) -> bool {
    matches!(f, MoveFailure::SourceMissing)
}
pub fn is_outcome_unknown_phase(phase: MovePhase) -> bool {
    matches!(
        phase,
        MovePhase::DestinationIdentity
            | MovePhase::PostLinearization
            | MovePhase::DestFsync
            | MovePhase::SourceFsync
    )
}
pub fn is_not_committed_phase(phase: MovePhase) -> bool {
    matches!(
        phase,
        MovePhase::EnsureDest | MovePhase::PreRename | MovePhase::Rename
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    fn open_unnamed_file(directory: BorrowedFd<'_>) -> Option<std::os::fd::OwnedFd> {
        let file = fs::open_tmpfile(directory).ok()?;
        fs::write_all(file.as_fd(), b"published").unwrap();
        Some(file)
    }

    #[test]
    fn tmpfile_open_fallback_errors_are_exact() {
        for (errno, expected) in [
            (libc::EISDIR, true),
            (libc::ENOENT, true),
            (libc::EOPNOTSUPP, true),
            (libc::EINVAL, false),
            (libc::EIO, false),
            (libc::ENOSPC, false),
            (libc::EPERM, false),
        ] {
            assert_eq!(
                is_tmpfile_open_unsupported(&std::io::Error::from_raw_os_error(errno)),
                expected,
                "errno {errno}"
            );
        }
    }

    #[test]
    fn tmpfile_identity_requires_an_unnamed_regular_file() {
        let root = tempfile::tempdir().unwrap();
        let directory = std::fs::File::open(root.path()).unwrap();
        let Some(tmpfile) = open_unnamed_file(directory.as_fd()) else {
            return;
        };
        let valid = fs::fstat(tmpfile.as_fd()).unwrap();
        let identity = unnamed_file_identity(&valid).unwrap();
        assert_eq!(identity.device, valid.st_dev);
        assert_eq!(identity.inode, valid.st_ino);

        let mut wrong_type = valid;
        wrong_type.st_mode = libc::S_IFDIR | 0o700;
        assert!(unnamed_file_identity(&wrong_type).is_err());

        let mut linked = valid;
        linked.st_nlink = 1;
        assert!(unnamed_file_identity(&linked).is_err());

        let mut negative_size = valid;
        negative_size.st_size = -1;
        assert!(unnamed_file_identity(&negative_size).is_err());
    }

    #[test]
    fn tmpfile_publication_uses_each_supported_link_strategy() {
        for force_proc in [false, true] {
            fs::fault::reset();
            let root = tempfile::tempdir().unwrap();
            let directory = std::fs::File::open(root.path()).unwrap();
            let Some(tmpfile) = open_unnamed_file(directory.as_fd()) else {
                return;
            };
            let source = fs::fstat(tmpfile.as_fd()).unwrap();
            if force_proc {
                fs::fault::inject_errno("linkat_empty_path", 1, libc::ENOENT);
                fs::fault::inject("linkat_proc_self_fd", u64::MAX);
            }

            let outcome =
                publish_tmpfile_noreplace(tmpfile.as_fd(), directory.as_fd(), "published.raw")
                    .unwrap();
            let empty_path_calls = fs::fault::call_count("linkat_empty_path");
            let proc_calls = fs::fault::call_count("linkat_proc_self_fd");
            fs::fault::reset();

            assert!(matches!(outcome, TmpfilePublishOutcome::Published(_)));
            let destination = fs::fstatat(directory.as_fd(), "published.raw").unwrap();
            assert_eq!(destination.st_dev, source.st_dev);
            assert_eq!(destination.st_ino, source.st_ino);
            if force_proc {
                assert_eq!(empty_path_calls, 1);
                assert_eq!(proc_calls, 1);
            }
        }
    }

    #[test]
    fn tmpfile_publication_reuses_a_successful_proc_strategy() {
        fs::fault::reset();
        let root = tempfile::tempdir().unwrap();
        let directory = std::fs::File::open(root.path()).unwrap();
        let Some(first_tmpfile) = open_unnamed_file(directory.as_fd()) else {
            return;
        };
        fs::fault::inject_errno("linkat_empty_path", 1, libc::ENOENT);
        fs::fault::inject("linkat_proc_self_fd", u64::MAX);

        let first = publish_tmpfile_noreplace_with_mode(
            first_tmpfile.as_fd(),
            directory.as_fd(),
            "first.raw",
            None,
        )
        .unwrap();
        let TmpfilePublishOutcome::Published(mode) = first else {
            panic!("proc publication unexpectedly unsupported");
        };
        assert_eq!(mode, fs::PublicationMode::ProcSelfFd);

        let Some(second_tmpfile) = open_unnamed_file(directory.as_fd()) else {
            fs::fault::reset();
            return;
        };
        let second = publish_tmpfile_noreplace_with_mode(
            second_tmpfile.as_fd(),
            directory.as_fd(),
            "second.raw",
            Some(mode),
        )
        .unwrap();
        let direct_calls = fs::fault::call_count("linkat_empty_path");
        let proc_calls = fs::fault::call_count("linkat_proc_self_fd");
        fs::fault::reset();

        assert!(matches!(
            second,
            TmpfilePublishOutcome::Published(fs::PublicationMode::ProcSelfFd)
        ));
        assert_eq!(direct_calls, 1, "the learned proc path skips direct link");
        assert_eq!(proc_calls, 2);
    }

    #[test]
    fn tmpfile_publication_falls_back_only_for_unsupported_strategies() {
        for (first_errno, second_errno, proc_calls) in [
            (libc::ENOSYS, None, 0),
            (libc::ENOENT, Some(libc::ENOENT), 1),
            (libc::EINVAL, Some(libc::EOPNOTSUPP), 1),
        ] {
            fs::fault::reset();
            let root = tempfile::tempdir().unwrap();
            let directory = std::fs::File::open(root.path()).unwrap();
            let Some(tmpfile) = open_unnamed_file(directory.as_fd()) else {
                return;
            };
            fs::fault::inject_errno("linkat_empty_path", 1, first_errno);
            if let Some(errno) = second_errno {
                fs::fault::inject_errno("linkat_proc_self_fd", 1, errno);
            }

            let outcome =
                publish_tmpfile_noreplace(tmpfile.as_fd(), directory.as_fd(), "published.raw")
                    .unwrap();
            assert!(matches!(outcome, TmpfilePublishOutcome::Unsupported));
            assert_eq!(fs::fault::call_count("linkat_proc_self_fd"), proc_calls);
            assert!(!root.path().join("published.raw").exists());
            fs::fault::reset();
        }
    }

    #[test]
    fn tmpfile_publication_does_not_treat_a_deleted_destination_as_unsupported() {
        fs::fault::reset();
        let root = tempfile::tempdir().unwrap();
        let destination_path = root.path().join("destination");
        std::fs::create_dir(&destination_path).unwrap();
        let directory = std::fs::File::open(&destination_path).unwrap();
        let Some(tmpfile) = open_unnamed_file(directory.as_fd()) else {
            return;
        };
        std::fs::remove_dir(&destination_path).unwrap();
        fs::fault::inject_errno("linkat_empty_path", 1, libc::ENOENT);
        fs::fault::inject_errno("linkat_proc_self_fd", 1, libc::ENOENT);

        let failure =
            publish_tmpfile_noreplace(tmpfile.as_fd(), directory.as_fd(), "published.raw")
                .unwrap_err();
        fs::fault::reset();

        assert!(matches!(
            failure,
            TmpfilePublishFailure::NotCommitted {
                phase: TmpfilePublishPhase::Link,
                ..
            }
        ));
    }

    #[test]
    fn tmpfile_publication_preserves_every_failure_phase() {
        for (first_fault, second_fault, expected_phase, outcome_unknown) in [
            (
                ("fstat", libc::EIO),
                None,
                TmpfilePublishPhase::SourceIdentity,
                false,
            ),
            (
                ("fsync", libc::EIO),
                None,
                TmpfilePublishPhase::FileFsync,
                false,
            ),
            (
                ("linkat_empty_path", libc::ENOSPC),
                None,
                TmpfilePublishPhase::Link,
                false,
            ),
            (
                ("linkat_empty_path", libc::ENOENT),
                Some(("linkat_proc_self_fd", libc::ENOSPC)),
                TmpfilePublishPhase::Link,
                false,
            ),
            (
                ("fsync_dir_fd", libc::EIO),
                None,
                TmpfilePublishPhase::DestinationFsync,
                true,
            ),
        ] {
            fs::fault::reset();
            let root = tempfile::tempdir().unwrap();
            let directory = std::fs::File::open(root.path()).unwrap();
            let Some(tmpfile) = open_unnamed_file(directory.as_fd()) else {
                return;
            };
            fs::fault::inject_errno(first_fault.0, 1, first_fault.1);
            if let Some((fault, errno)) = second_fault {
                fs::fault::inject_errno(fault, 1, errno);
            }

            let failure =
                publish_tmpfile_noreplace(tmpfile.as_fd(), directory.as_fd(), "published.raw")
                    .unwrap_err();
            fs::fault::reset();

            assert_eq!(failure.phase(), Some(expected_phase));
            assert_eq!(failure.is_outcome_unknown(), outcome_unknown);
            assert_eq!(root.path().join("published.raw").exists(), outcome_unknown);
        }
    }

    #[test]
    fn tmpfile_publication_collision_does_not_try_a_weaker_strategy() {
        for force_proc in [false, true] {
            fs::fault::reset();
            let root = tempfile::tempdir().unwrap();
            let directory = std::fs::File::open(root.path()).unwrap();
            let Some(tmpfile) = open_unnamed_file(directory.as_fd()) else {
                return;
            };
            if force_proc {
                fs::fault::inject_errno("linkat_empty_path", 1, libc::ENOENT);
                fs::fault::inject_errno("linkat_proc_self_fd", 1, libc::EEXIST);
            } else {
                fs::fault::inject_errno("linkat_empty_path", 1, libc::EEXIST);
                fs::fault::inject("linkat_proc_self_fd", u64::MAX);
            }

            let failure =
                publish_tmpfile_noreplace(tmpfile.as_fd(), directory.as_fd(), "published.raw")
                    .unwrap_err();
            let proc_calls = fs::fault::call_count("linkat_proc_self_fd");
            fs::fault::reset();

            assert!(matches!(failure, TmpfilePublishFailure::AlreadyExists));
            assert_eq!(proc_calls, u64::from(force_proc));
            assert!(!root.path().join("published.raw").exists());
        }
    }

    #[test]
    fn is_already_exists_table() {
        assert!(is_already_exists(&MoveFailure::AlreadyExists));
        assert!(!is_already_exists(&MoveFailure::SourceMissing));
        assert!(!is_already_exists(&MoveFailure::NotCommitted {
            phase: MovePhase::Rename,
            source: std::io::Error::other("x")
        }));
        assert!(!is_already_exists(&MoveFailure::OutcomeUnknown {
            phase: MovePhase::DestFsync,
            source: std::io::Error::other("y")
        }));
    }

    #[test]
    fn is_source_missing_table() {
        assert!(is_source_missing(&MoveFailure::SourceMissing));
        assert!(!is_source_missing(&MoveFailure::AlreadyExists));
        assert!(!is_source_missing(&MoveFailure::NotCommitted {
            phase: MovePhase::PreRename,
            source: std::io::Error::other("z")
        }));
    }

    #[test]
    fn is_outcome_unknown_phase_table() {
        assert!(is_outcome_unknown_phase(MovePhase::DestinationIdentity));
        assert!(is_outcome_unknown_phase(MovePhase::PostLinearization));
        assert!(is_outcome_unknown_phase(MovePhase::DestFsync));
        assert!(is_outcome_unknown_phase(MovePhase::SourceFsync));
        assert!(!is_outcome_unknown_phase(MovePhase::Rename));
        assert!(!is_outcome_unknown_phase(MovePhase::EnsureDest));
        assert!(!is_outcome_unknown_phase(MovePhase::PreRename));
    }

    #[test]
    fn is_not_committed_phase_table() {
        assert!(is_not_committed_phase(MovePhase::EnsureDest));
        assert!(is_not_committed_phase(MovePhase::PreRename));
        assert!(is_not_committed_phase(MovePhase::Rename));
        assert!(!is_not_committed_phase(MovePhase::DestinationIdentity));
        assert!(!is_not_committed_phase(MovePhase::PostLinearization));
        assert!(!is_not_committed_phase(MovePhase::DestFsync));
        assert!(!is_not_committed_phase(MovePhase::SourceFsync));
    }

    #[test]
    fn move_failure_phase_extraction() {
        let f: MoveFailure = MoveFailure::NotCommitted {
            phase: MovePhase::Rename,
            source: std::io::Error::other("a"),
        };
        assert_eq!(f.phase(), Some(MovePhase::Rename));
        assert!(f.is_not_committed());
        assert!(!f.is_outcome_unknown());

        let g: MoveFailure = MoveFailure::OutcomeUnknown {
            phase: MovePhase::SourceFsync,
            source: std::io::Error::other("b"),
        };
        assert_eq!(g.phase(), Some(MovePhase::SourceFsync));
        assert!(g.is_outcome_unknown());
        assert!(!g.is_not_committed());

        assert_eq!(MoveFailure::AlreadyExists.phase(), None);
        assert_eq!(MoveFailure::SourceMissing.phase(), None);
    }

    #[test]
    fn map_move_failure_covers_variants() {
        let e = map_move_failure(MoveFailure::AlreadyExists);
        assert!(matches!(e, Error::QueueCorrupt(_)));
        let e = map_move_failure(MoveFailure::SourceMissing);
        assert!(matches!(e, Error::QueueCorrupt(_)));
        let e = map_move_failure(MoveFailure::NotCommitted {
            phase: MovePhase::Rename,
            source: std::io::Error::other("io"),
        });
        assert!(matches!(e, Error::IoFailure(_)));
        let e = map_move_failure(MoveFailure::OutcomeUnknown {
            phase: MovePhase::DestFsync,
            source: std::io::Error::other("fsync"),
        });
        assert!(matches!(e, Error::IoFailure(_)));
    }

    #[test]
    fn is_already_exists_io_kind_table() {
        assert!(is_already_exists_io_kind(std::io::ErrorKind::AlreadyExists));
        assert!(!is_already_exists_io_kind(std::io::ErrorKind::NotFound));
        assert!(!is_already_exists_io_kind(
            std::io::ErrorKind::PermissionDenied
        ));
        assert!(!is_already_exists_io_kind(std::io::ErrorKind::Other));
        assert!(!is_already_exists_io_kind(std::io::ErrorKind::Interrupted));
    }

    #[test]
    fn is_not_found_io_kind_table() {
        assert!(is_not_found_io_kind(std::io::ErrorKind::NotFound));
        assert!(!is_not_found_io_kind(std::io::ErrorKind::AlreadyExists));
        assert!(!is_not_found_io_kind(std::io::ErrorKind::PermissionDenied));
        assert!(!is_not_found_io_kind(std::io::ErrorKind::Other));
        assert!(!is_not_found_io_kind(std::io::ErrorKind::Interrupted));
    }

    #[test]
    fn move_verified_noreplace_bad_fd_is_not_committed() {
        // EBADF should map to NotCommitted, not SourceMissing, to kill the
        // match guard mutant that replaces is_not_found_io_kind with true.
        let dir = tempfile::tempdir().unwrap();
        let dest_dir = tempfile::tempdir_in(dir.path()).unwrap();
        let dest_fd = std::fs::OpenOptions::new()
            .read(true)
            .open(dest_dir.path())
            .unwrap();
        fs::fault::reset();
        fs::fault::inject_errno("renameat2_noreplace", 1, libc::EIO);
        let r = move_verified_noreplace(dest_fd.as_fd(), "nope.raw", dest_fd.as_fd(), "dest.raw");
        fs::fault::reset();
        assert!(matches!(
            &r,
            Err(MoveFailure::NotCommitted {
                phase: MovePhase::Rename,
                ..
            })
        ));
        assert!(r.as_ref().unwrap_err().is_not_committed());
        assert!(!matches!(&r, Ok(())));
        // Ensure it is not misclassified as SourceMissing when guard is true
        assert!(!matches!(&r, Err(MoveFailure::SourceMissing)));
    }

    #[test]
    fn durable_move_round_trip_tmpdir() {
        let dir = tempfile::tempdir().unwrap();
        let src_dir = tempfile::tempdir_in(dir.path()).unwrap();
        let dest_dir = tempfile::tempdir_in(dir.path()).unwrap();
        let src_path = src_dir.path().join("src.raw");
        std::fs::write(&src_path, b"hello").unwrap();
        let src_fd = std::fs::OpenOptions::new()
            .read(true)
            .open(src_dir.path())
            .unwrap();
        let dest_fd = std::fs::OpenOptions::new()
            .read(true)
            .open(dest_dir.path())
            .unwrap();
        let r = move_verified_noreplace(src_fd.as_fd(), "src.raw", dest_fd.as_fd(), "dest.raw");
        assert!(r.is_ok());
        assert!(dest_dir.path().join("dest.raw").exists());
        assert!(!src_dir.path().join("src.raw").exists());

        // second move of same source should be SourceMissing
        let r2 = move_verified_noreplace(src_fd.as_fd(), "src.raw", dest_fd.as_fd(), "dest2.raw");
        assert!(matches!(r2, Err(MoveFailure::SourceMissing)));

        // recreate source and try to overwrite existing dest
        std::fs::write(src_dir.path().join("src.raw"), b"again").unwrap();
        let r3 = move_verified_noreplace(src_fd.as_fd(), "src.raw", dest_fd.as_fd(), "dest.raw");
        assert!(matches!(r3, Err(MoveFailure::AlreadyExists)));
    }

    #[test]
    fn move_identity_requires_exact_singly_linked_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source.raw");
        std::fs::write(&path, b"source").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let stat = fs::fstat(file.as_fd()).unwrap();
        let identity = MoveIdentity::new(stat.st_dev, stat.st_ino);

        assert!(identity.matches(&stat));

        let mut wrong_type = stat;
        wrong_type.st_mode = libc::S_IFDIR | 0o700;
        assert!(!identity.matches(&wrong_type));

        let mut wrong_link_count = stat;
        wrong_link_count.st_nlink = 2;
        assert!(!identity.matches(&wrong_link_count));

        let mut negative_size = stat;
        negative_size.st_size = -1;
        assert!(!identity.matches(&negative_size));

        let mut wrong_device = stat;
        wrong_device.st_dev = wrong_device.st_dev.wrapping_add(1);
        assert!(!identity.matches(&wrong_device));

        let mut wrong_inode = stat;
        wrong_inode.st_ino = wrong_inode.st_ino.wrapping_add(1);
        assert!(!identity.matches(&wrong_inode));
    }

    #[test]
    fn witnessed_move_preserves_every_failure_phase() {
        for (fault, fault_count, expected_phase, source_remains) in [
            ("renameat2_noreplace", 1, MovePhase::Rename, true),
            ("fstatat", 1, MovePhase::DestinationIdentity, false),
            ("fsync_dir_fd", 1, MovePhase::DestFsync, false),
            ("fsync_dir_fd", 2, MovePhase::SourceFsync, false),
        ] {
            let root = tempfile::tempdir().unwrap();
            let source_dir = root.path().join("source");
            let destination_dir = root.path().join("destination");
            std::fs::create_dir(&source_dir).unwrap();
            std::fs::create_dir(&destination_dir).unwrap();
            std::fs::write(source_dir.join("source.raw"), b"source").unwrap();
            let source_fd = std::fs::File::open(&source_dir).unwrap();
            let destination_fd = std::fs::File::open(&destination_dir).unwrap();
            let source_stat = fs::fstatat(source_fd.as_fd(), "source.raw").unwrap();

            fs::fault::reset();
            fs::fault::inject_errno(fault, fault_count, libc::EIO);
            let failure = move_witnessed_noreplace(
                source_fd.as_fd(),
                "source.raw",
                destination_fd.as_fd(),
                "destination.raw",
                MoveIdentity::new(source_stat.st_dev, source_stat.st_ino),
            )
            .unwrap_err();
            fs::fault::reset();

            assert_eq!(failure.phase(), Some(expected_phase));
            assert_eq!(failure.is_outcome_unknown(), !source_remains);
            assert_eq!(source_dir.join("source.raw").exists(), source_remains);
            assert_eq!(
                destination_dir.join("destination.raw").exists(),
                !source_remains
            );
        }
    }

    #[test]
    fn witnessed_move_rejects_the_wrong_destination_identity() {
        let root = tempfile::tempdir().unwrap();
        let source_dir = root.path().join("source");
        let destination_dir = root.path().join("destination");
        std::fs::create_dir(&source_dir).unwrap();
        std::fs::create_dir(&destination_dir).unwrap();
        std::fs::write(source_dir.join("source.raw"), b"source").unwrap();
        let source_fd = std::fs::File::open(&source_dir).unwrap();
        let destination_fd = std::fs::File::open(&destination_dir).unwrap();
        let source_stat = fs::fstatat(source_fd.as_fd(), "source.raw").unwrap();

        let failure = move_witnessed_noreplace(
            source_fd.as_fd(),
            "source.raw",
            destination_fd.as_fd(),
            "destination.raw",
            MoveIdentity::new(source_stat.st_dev, source_stat.st_ino.wrapping_add(1)),
        )
        .unwrap_err();

        assert!(matches!(
            failure,
            MoveFailure::OutcomeUnknown {
                phase: MovePhase::DestinationIdentity,
                ..
            }
        ));
        assert!(!source_dir.join("source.raw").exists());
        assert!(destination_dir.join("destination.raw").exists());
    }

    #[test]
    fn witnessed_move_syncs_same_directory_once_across_distinct_fds() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("source.raw"), b"source").unwrap();
        let source_fd = std::fs::File::open(dir.path()).unwrap();
        let destination_fd = std::fs::File::open(dir.path()).unwrap();
        let source_stat = fs::fstatat(source_fd.as_fd(), "source.raw").unwrap();

        fs::fault::reset();
        fs::fault::inject_errno("fsync_dir_fd", 2, libc::EIO);
        move_witnessed_noreplace(
            source_fd.as_fd(),
            "source.raw",
            destination_fd.as_fd(),
            "destination.raw",
            MoveIdentity::new(source_stat.st_dev, source_stat.st_ino),
        )
        .unwrap();
        assert_eq!(fs::fault::call_count("fsync_dir_fd"), 1);
        fs::fault::reset();
    }

    #[test]
    fn witnessed_move_runs_post_linearization_work_before_barriers() {
        let root = tempfile::tempdir().unwrap();
        let source_dir = root.path().join("source");
        let destination_dir = root.path().join("destination");
        std::fs::create_dir(&source_dir).unwrap();
        std::fs::create_dir(&destination_dir).unwrap();
        let contents = b"source evidence";
        std::fs::write(source_dir.join("source.raw"), contents).unwrap();
        let source_fd = std::fs::File::open(&source_dir).unwrap();
        let destination_fd = std::fs::File::open(&destination_dir).unwrap();
        let source_stat = fs::fstatat(source_fd.as_fd(), "source.raw").unwrap();

        fs::fault::reset();
        let failure = move_witnessed_noreplace_with(
            source_fd.as_fd(),
            "source.raw",
            destination_fd.as_fd(),
            "destination.raw",
            MoveIdentity::new(source_stat.st_dev, source_stat.st_ino),
            |moved| {
                assert!(!source_dir.join("source.raw").exists());
                assert!(destination_dir.join("destination.raw").exists());
                assert_eq!(moved.device(), source_stat.st_dev);
                assert_eq!(moved.inode(), source_stat.st_ino);
                assert_eq!(moved.size(), contents.len() as u64);
                Err::<(), _>(std::io::Error::other("evidence refresh failed"))
            },
        )
        .unwrap_err();

        assert!(matches!(
            failure,
            MoveFailure::OutcomeUnknown {
                phase: MovePhase::PostLinearization,
                ..
            }
        ));
        assert_eq!(fs::fault::call_count("fsync_dir_fd"), 0);
        fs::fault::reset();
    }

    #[test]
    fn witnessed_io_move_preserves_the_underlying_error() {
        for (fault, fault_count, errno, expected_phase, outcome_unknown) in [
            (
                "renameat2_noreplace",
                1,
                libc::ENOSPC,
                MovePhase::Rename,
                false,
            ),
            ("fsync_dir_fd", 1, libc::EIO, MovePhase::DestFsync, true),
        ] {
            let root = tempfile::tempdir().unwrap();
            let source_dir = root.path().join("source");
            let destination_dir = root.path().join("destination");
            std::fs::create_dir(&source_dir).unwrap();
            std::fs::create_dir(&destination_dir).unwrap();
            std::fs::write(source_dir.join("source.raw"), b"source").unwrap();
            let source_fd = std::fs::File::open(&source_dir).unwrap();
            let destination_fd = std::fs::File::open(&destination_dir).unwrap();
            let source_stat = fs::fstatat(source_fd.as_fd(), "source.raw").unwrap();

            fs::fault::reset();
            fs::fault::inject_errno(fault, fault_count, errno);
            let failure = move_witnessed_noreplace_io(
                source_fd.as_fd(),
                "source.raw",
                destination_fd.as_fd(),
                "destination.raw",
                MoveIdentity::new(source_stat.st_dev, source_stat.st_ino),
            )
            .unwrap_err();
            fs::fault::reset();

            assert_eq!(failure.phase(), Some(expected_phase));
            assert_eq!(failure.is_outcome_unknown(), outcome_unknown);
            let source = match failure {
                MoveFailureWith::NotCommitted { source, .. }
                | MoveFailureWith::OutcomeUnknown { source, .. } => source,
                other => panic!("expected I/O failure, got {other:?}"),
            };
            assert_eq!(source.raw_os_error(), Some(errno));
        }
    }

    #[test]
    fn unlink_verified_preserves_linearization_phase() {
        for (fault, expected_phase, outcome_unknown, file_remains) in [
            ("unlinkat", UnlinkPhase::Unlink, false, true),
            ("fsync_dir_fd", UnlinkPhase::DirectoryFsync, true, false),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("object.raw");
            std::fs::write(&path, b"object").unwrap();
            let directory_fd = std::fs::OpenOptions::new()
                .read(true)
                .open(dir.path())
                .unwrap();
            fs::fault::reset();
            fs::fault::inject_errno(fault, 1, libc::EIO);
            let result = unlink_verified(directory_fd.as_fd(), "object.raw");
            fs::fault::reset();
            let failure = result.unwrap_err();
            assert_eq!(failure.phase(), Some(expected_phase));
            assert_eq!(failure.is_outcome_unknown(), outcome_unknown);
            assert_eq!(path.exists(), file_remains);
        }
    }

    #[test]
    fn unlink_verified_distinguishes_missing_source_and_io_failure() {
        let dir = tempfile::tempdir().unwrap();
        let directory_fd = std::fs::OpenOptions::new()
            .read(true)
            .open(dir.path())
            .unwrap();
        assert!(matches!(
            unlink_verified(directory_fd.as_fd(), "missing.raw"),
            Err(UnlinkFailure::SourceMissing)
        ));
        fs::fault::reset();
        fs::fault::inject_errno("unlinkat", 1, libc::EIO);
        assert!(matches!(
            unlink_verified(directory_fd.as_fd(), "missing.raw"),
            Err(UnlinkFailure::NotCommitted {
                phase: UnlinkPhase::Unlink,
                ..
            })
        ));
        fs::fault::reset();
    }

    #[test]
    fn directory_not_empty_error_classification_is_exact() {
        assert!(is_directory_not_empty(&std::io::Error::from_raw_os_error(
            libc::ENOTEMPTY
        )));
        assert!(is_directory_not_empty(&std::io::Error::from_raw_os_error(
            libc::EEXIST
        )));
        assert!(!is_directory_not_empty(&std::io::Error::from_raw_os_error(
            libc::ENOENT
        )));
        assert!(!is_directory_not_empty(&std::io::Error::from_raw_os_error(
            libc::EIO
        )));
    }

    #[test]
    fn remove_empty_directory_preserves_linearization_phase_and_replays() {
        for (fault, expected_phase, outcome_unknown, directory_remains) in [
            ("unlinkat_dir", RemoveDirectoryPhase::Remove, false, true),
            (
                "fsync_dir_fd",
                RemoveDirectoryPhase::ParentFsync,
                true,
                false,
            ),
        ] {
            let root = tempfile::tempdir().unwrap();
            std::fs::create_dir(root.path().join("empty")).unwrap();
            std::fs::write(root.path().join("sibling"), b"distinct").unwrap();
            let parent = std::fs::OpenOptions::new()
                .read(true)
                .open(root.path())
                .unwrap();
            fs::fault::reset();
            fs::fault::inject_errno(fault, 1, libc::EIO);
            let result = remove_empty_directory_verified(parent.as_fd(), "empty");
            fs::fault::reset();
            let failure = result.unwrap_err();
            assert_eq!(failure.phase(), Some(expected_phase));
            assert_eq!(failure.is_outcome_unknown(), outcome_unknown);
            assert_eq!(root.path().join("empty").exists(), directory_remains);
            assert_eq!(
                std::fs::read(root.path().join("sibling")).unwrap(),
                b"distinct"
            );

            drop(parent);
            let reopened = std::fs::OpenOptions::new()
                .read(true)
                .open(root.path())
                .unwrap();
            let replay = remove_empty_directory_verified(reopened.as_fd(), "empty");
            if directory_remains {
                assert!(replay.is_ok());
            } else {
                assert!(matches!(replay, Err(RemoveDirectoryFailure::SourceMissing)));
            }
        }
    }

    #[test]
    fn remove_empty_directory_distinguishes_missing_nonempty_and_io() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("nonempty")).unwrap();
        std::fs::write(root.path().join("nonempty/object"), b"object").unwrap();
        let parent = std::fs::OpenOptions::new()
            .read(true)
            .open(root.path())
            .unwrap();
        assert!(matches!(
            remove_empty_directory_verified(parent.as_fd(), "missing"),
            Err(RemoveDirectoryFailure::SourceMissing)
        ));
        assert!(matches!(
            remove_empty_directory_verified(parent.as_fd(), "nonempty"),
            Err(RemoveDirectoryFailure::NotEmpty)
        ));
        fs::fault::reset();
        fs::fault::inject_errno("unlinkat_dir", 1, libc::EIO);
        assert!(matches!(
            remove_empty_directory_verified(parent.as_fd(), "missing"),
            Err(RemoveDirectoryFailure::NotCommitted {
                phase: RemoveDirectoryPhase::Remove,
                ..
            })
        ));
        fs::fault::reset();
        assert!(root.path().join("nonempty/object").exists());
    }

    #[test]
    fn replace_verified_preserves_linearization_phase() {
        for (fault, expected_phase, outcome_unknown, source_remains) in [
            ("renameat", ReplacePhase::Rename, false, true),
            ("fsync_dir_fd", ReplacePhase::DestinationFsync, true, false),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let source = dir.path().join("replacement.tmp");
            let destination = dir.path().join("receipt.rct");
            std::fs::write(&source, b"new").unwrap();
            std::fs::write(&destination, b"old").unwrap();
            let directory_fd = std::fs::OpenOptions::new()
                .read(true)
                .open(dir.path())
                .unwrap();
            fs::fault::reset();
            fs::fault::inject_errno(fault, 1, libc::EIO);
            let result = replace_verified(
                directory_fd.as_fd(),
                "replacement.tmp",
                directory_fd.as_fd(),
                "receipt.rct",
                None,
            );
            fs::fault::reset();
            let failure = result.unwrap_err();
            assert_eq!(failure.phase(), Some(expected_phase));
            assert_eq!(failure.is_outcome_unknown(), outcome_unknown);
            assert_eq!(source.exists(), source_remains);
            assert_eq!(
                std::fs::read(destination).unwrap(),
                if source_remains { b"old" } else { b"new" }
            );
        }
    }

    #[test]
    fn replace_verified_distinguishes_missing_source_and_io_failure() {
        let dir = tempfile::tempdir().unwrap();
        let directory_fd = std::fs::OpenOptions::new()
            .read(true)
            .open(dir.path())
            .unwrap();
        assert!(matches!(
            replace_verified(
                directory_fd.as_fd(),
                "missing.tmp",
                directory_fd.as_fd(),
                "receipt.rct",
                None
            ),
            Err(ReplaceFailure::SourceMissing)
        ));
        std::fs::write(dir.path().join("source.tmp"), b"new").unwrap();
        fs::fault::reset();
        fs::fault::inject_errno("renameat", 1, libc::EIO);
        assert!(matches!(
            replace_verified(
                directory_fd.as_fd(),
                "source.tmp",
                directory_fd.as_fd(),
                "receipt.rct",
                None
            ),
            Err(ReplaceFailure::NotCommitted {
                phase: ReplacePhase::Rename,
                ..
            })
        ));
        fs::fault::reset();
    }

    #[test]
    fn replace_verified_classifies_cross_directory_post_rename_failures() {
        for (fault, fault_count, expected_phase) in [
            ("fstat", 1, ReplacePhase::DirectoryIdentity),
            ("fstat", 2, ReplacePhase::DirectoryIdentity),
            ("fsync_dir_fd", 1, ReplacePhase::DestinationFsync),
            ("fsync_dir_fd", 2, ReplacePhase::SourceFsync),
        ] {
            let root = tempfile::tempdir().unwrap();
            let source_dir = root.path().join("source");
            let destination_dir = root.path().join("destination");
            std::fs::create_dir(&source_dir).unwrap();
            std::fs::create_dir(&destination_dir).unwrap();
            std::fs::write(source_dir.join("replacement.tmp"), b"new").unwrap();
            std::fs::write(destination_dir.join("receipt.rct"), b"old").unwrap();
            let source_fd = std::fs::OpenOptions::new()
                .read(true)
                .open(&source_dir)
                .unwrap();
            let destination_fd = std::fs::OpenOptions::new()
                .read(true)
                .open(&destination_dir)
                .unwrap();

            fs::fault::reset();
            fs::fault::inject_errno(fault, fault_count, libc::EIO);
            let failure = replace_verified(
                source_fd.as_fd(),
                "replacement.tmp",
                destination_fd.as_fd(),
                "receipt.rct",
                None,
            )
            .unwrap_err();
            fs::fault::reset();

            assert_eq!(failure.phase(), Some(expected_phase));
            assert!(failure.is_outcome_unknown());
            assert!(!source_dir.join("replacement.tmp").exists());
            assert_eq!(
                std::fs::read(destination_dir.join("receipt.rct")).unwrap(),
                b"new"
            );
        }
    }

    #[test]
    fn replace_verified_syncs_one_directory_for_distinct_fds_to_same_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("replacement.tmp"), b"new").unwrap();
        std::fs::write(dir.path().join("receipt.rct"), b"old").unwrap();
        let source_fd = std::fs::OpenOptions::new()
            .read(true)
            .open(dir.path())
            .unwrap();
        let destination_fd = std::fs::OpenOptions::new()
            .read(true)
            .open(dir.path())
            .unwrap();

        fs::fault::reset();
        fs::fault::inject_errno("fsync_dir_fd", 2, libc::EIO);
        replace_verified(
            source_fd.as_fd(),
            "replacement.tmp",
            destination_fd.as_fd(),
            "receipt.rct",
            None,
        )
        .unwrap();
        assert_eq!(fs::fault::call_count("fsync_dir_fd"), 1);
        fs::fault::reset();
    }

    #[test]
    fn replace_verified_revalidates_destination_immediately_before_rename() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("replacement.tmp");
        let destination = dir.path().join("receipt.rct");
        std::fs::write(&source, b"new").unwrap();
        std::fs::write(&destination, b"old").unwrap();
        let directory_fd = std::fs::OpenOptions::new()
            .read(true)
            .open(dir.path())
            .unwrap();
        let destination_stat = fs::fstatat(directory_fd.as_fd(), "receipt.rct").unwrap();

        let changed = replace_verified(
            directory_fd.as_fd(),
            "replacement.tmp",
            directory_fd.as_fd(),
            "receipt.rct",
            Some(ReplaceIdentity::new(
                destination_stat.st_dev,
                destination_stat.st_ino.wrapping_add(1),
            )),
        );
        assert!(matches!(changed, Err(ReplaceFailure::DestinationChanged)));
        assert!(source.exists());
        assert_eq!(std::fs::read(&destination).unwrap(), b"old");

        replace_verified(
            directory_fd.as_fd(),
            "replacement.tmp",
            directory_fd.as_fd(),
            "receipt.rct",
            Some(ReplaceIdentity::new(
                destination_stat.st_dev,
                destination_stat.st_ino,
            )),
        )
        .unwrap();
        assert!(!source.exists());
        assert_eq!(std::fs::read(destination).unwrap(), b"new");
    }
}
