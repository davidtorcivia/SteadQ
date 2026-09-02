// Queue handle: init, open, directory helpers, and operation modules.

mod batch;
mod consumer;
mod cursors;
pub mod engine;
mod inspect;
pub(crate) use inspect::{copy_file_to_path, raw_read_open_flags};
pub mod layout;
mod lease;
mod options;
mod publish;
mod resolve;
pub mod verified;
mod watermark;

pub use batch::*;
pub(crate) use cursors::*;
pub use options::*;
pub use watermark::*;

use std::io;
use std::os::unix::io::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use steadq_format::cbor::ExtensionHeader;

use steadq_format::{
    envelope_digest, payload_digest, FixedHeader, FormatRecord, WatermarkRecord,
    DIGEST_ALGORITHM_SHA256, FORMAT_MINOR, MAX_PAYLOAD_LENGTH,
};
use steadq_fs_linux as fs;
use steadq_math::{self, bucket_number, ceiling_bucket, eligibility_bucket_and_ns};
use steadq_names::{self, bucket_hex, compute_shard, shard_hex, temp_filename, CommonFields};

use crate::errors::*;
use crate::state_machine::{ObjectKind, Operation as ProtocolOperation};

pub struct Queue {
    pub(crate) root_fd: OwnedFd,
    pub(crate) root_path: PathBuf,
    pub(crate) format: FormatRecord,
    pub(crate) boot_id: String,
    pub(crate) boot_id_bytes: [u8; 16],
    pub(crate) poisoned: bool,
    pub(crate) scan_round: u64,
    pub(crate) ready_shard_hint: Option<u32>,
    pub(crate) worker_nonce: [u8; 16],
    pub(crate) options: OpenOptions,
    // Held so the shared OFD lock lives as long as the Queue.
    _maint_lock_fd: Option<OwnedFd>,
    pub(crate) recovery_cursor: RecoveryCursor,
    pub(crate) cached_wall_floor: Option<WallFloor>,
    pub(crate) cached_watermark_fd: std::cell::RefCell<Option<OwnedFd>>,
    pub(crate) known_dirs: std::cell::RefCell<std::collections::HashSet<String>>,
    pub(crate) cached_dest_fd: Option<(String, std::os::fd::OwnedFd)>,
    pub(crate) publication_mode: Option<fs::PublicationMode>,
    pub(crate) deferred_dir_sync: bool,
    pub(crate) dirty: std::cell::RefCell<engine::DirtySet>,
    // inotify hint for the lease wait; None means poll-only. Advisory only.
    pub(crate) ready_watch: Option<std::os::fd::OwnedFd>,
    pub(crate) ready_watch_attempted: bool,
}

pub(super) struct ClaimSourceWitness {
    file_fd: OwnedFd,
    device: u64,
    inode: u64,
    evidence: TicketEvidence,
}

pub(super) struct LeasedSourceWitness {
    directory_fd: OwnedFd,
    name: String,
    file_fd: OwnedFd,
    device: u64,
    inode: u64,
}

/// A reader for a verified lease payload that does not re-hash on each read.
///
/// The payload is verified once at construction. Subsequent `read_at` calls
/// perform direct pread on the held fd, avoiding the O(n^2) cost of calling
/// `read_lease_payload_chunk` repeatedly.
pub struct VerifiedPayloadReader {
    file_fd: OwnedFd,
    payload_start: u64,
    payload_len: u64,
}

impl VerifiedPayloadReader {
    /// Read payload bytes at the given offset into buf.
    /// Returns the number of bytes read (0 at EOF).
    pub fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize, Error> {
        if offset >= self.payload_len {
            return Ok(0);
        }
        let to_read = (buf.len() as u64).min(self.payload_len - offset) as usize;
        let abs_offset = self.payload_start + offset;
        let n = fs::pread(self.file_fd.as_fd(), &mut buf[..to_read], abs_offset)
            .map_err(Error::from)?;
        Ok(n)
    }

    /// Total payload length in bytes.
    pub fn payload_len(&self) -> u64 {
        self.payload_len
    }
}

#[derive(Debug)]
pub(super) enum LeasedMoveOutcome {
    Committed,
    OutcomeUnknown(TransitionPhase),
    SourceGone,
    SourceChanged,
    Collision,
    Failed(Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WitnessPathObservation {
    Match,
    Gone,
    Mismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LeaseDirectoryOpenFailure {
    Gone,
    InvalidDirectory,
    Io,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PresenceFailure {
    Absent,
    Io,
}

pub(super) fn observe_witness_path(
    directory_fd: BorrowedFd<'_>,
    name: &str,
    device: u64,
    inode: u64,
) -> Result<WitnessPathObservation, Error> {
    match fs::fstatat(directory_fd, name) {
        Ok(stat) if stat_matches_witness(&stat, device, inode) => Ok(WitnessPathObservation::Match),
        Ok(_) => Ok(WitnessPathObservation::Mismatch),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
            Ok(WitnessPathObservation::Gone)
        }
        Err(error) => Err(Error::from(error)),
    }
}

pub(super) fn is_singly_linked_regular(mode: libc::mode_t, link_count: libc::nlink_t) -> bool {
    mode & libc::S_IFMT == libc::S_IFREG && link_count == 1
}

pub(super) fn stat_matches_witness(stat: &libc::stat, device: u64, inode: u64) -> bool {
    is_singly_linked_regular(stat.st_mode, stat.st_nlink)
        && identity_matches(stat.st_dev, stat.st_ino, device, inode)
}

pub(super) fn resolver_file_open_flags() -> i32 {
    libc::O_NOFOLLOW
        .checked_add(libc::O_CLOEXEC)
        .and_then(|flags| flags.checked_add(libc::O_NONBLOCK))
        .expect("Linux open flags fit i32")
}

pub(super) fn classify_lease_directory_open_failure(
    error: &io::Error,
) -> LeaseDirectoryOpenFailure {
    match error.raw_os_error() {
        Some(libc::ENOENT) => LeaseDirectoryOpenFailure::Gone,
        Some(libc::ENOTDIR) => LeaseDirectoryOpenFailure::InvalidDirectory,
        _ => LeaseDirectoryOpenFailure::Io,
    }
}

pub(super) fn classify_presence_failure(error: &io::Error) -> PresenceFailure {
    match error.raw_os_error() {
        Some(libc::ENOENT) => PresenceFailure::Absent,
        _ => PresenceFailure::Io,
    }
}

pub(super) fn ticket_phase_for_move_outcome_unknown(phase: engine::MovePhase) -> TransitionPhase {
    match phase {
        engine::MovePhase::SourceFsync => TransitionPhase::DestinationDirectoryDurable,
        engine::MovePhase::EnsureDest
        | engine::MovePhase::PreRename
        | engine::MovePhase::Rename
        | engine::MovePhase::DestinationIdentity
        | engine::MovePhase::PostLinearization
        | engine::MovePhase::DestFsync => TransitionPhase::Linearized,
    }
}

pub(super) fn identity_matches(
    device: u64,
    inode: u64,
    expected_device: u64,
    expected_inode: u64,
) -> bool {
    device == expected_device && inode == expected_inode
}

pub(super) fn lease_common(lease: &LeaseInfo) -> CommonFields {
    CommonFields {
        job_id: lease.job_id,
        generation: lease.generation,
        attempt: lease.attempt,
        maximum_attempts: lease.maximum_attempts,
    }
}

pub(super) fn next_identity(
    operation: ProtocolOperation,
    source: &CommonFields,
) -> Result<CommonFields, Error> {
    next_common_fields(operation, source).map_err(|error| match error {
        IdentityChangeError::Overflow => Error::StateExhausted,
        IdentityChangeError::Indeterminate => {
            Error::InvalidInput("operation has an indeterminate generation change".into())
        }
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RetryTiming {
    Immediate,
    Delayed {
        not_before_ns: u64,
        wall_floor: WallFloor,
    },
}

pub(super) fn preferred_publication_mode(filesystem_type: i64) -> Option<fs::PublicationMode> {
    // OpenZFS can stall O_TMPFILE link publication behind transaction-group
    // work; its ordinary named-temp rename path avoids that slow path while
    // retaining the same no-overwrite and durability checks.
    (filesystem_type == fs::ZFS_SUPER_MAGIC).then_some(fs::PublicationMode::NamedFallback)
}

pub(super) fn classify_filesystem_type(
    observation: io::Result<i64>,
    allow_unsupported: bool,
) -> Result<Option<i64>, Error> {
    match observation {
        Ok(filesystem_type)
            if allow_unsupported || fs::supported_filesystem_name(filesystem_type).is_some() =>
        {
            Ok(Some(filesystem_type))
        }
        Ok(_) => Err(Error::UnsupportedFilesystem),
        Err(_) if allow_unsupported => Ok(None),
        Err(error) => Err(Error::from(error)),
    }
}

/// Active path context for tag authentication.
#[derive(Clone, Debug)]
pub enum ActivePathContext {
    Ready {
        shard: String,
    },
    Leased {
        boot_id: String,
        bucket: String,
        shard: String,
    },
    Delayed {
        bucket: String,
        shard: String,
    },
}

impl Queue {
    /// Initialize a new queue at the given path.
    pub fn init(root: &Path, opts: &CreateOptions) -> io::Result<FormatRecord> {
        // Validate all options before any filesystem mutation
        validate_create_options(opts)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

        // Preflight filesystem check before any mutation.
        // If the root already exists, check its filesystem. If creating,
        // check the parent's filesystem.
        let check_path = if root.exists() {
            root
        } else {
            root.parent().unwrap_or(root)
        };
        let ft =
            fs::fs_type_magic(check_path).map_err(|e| io::Error::other(format!("statfs: {e}")))?;
        if fs::supported_filesystem_name(ft).is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "filesystem type not supported for queue (observed magic {ft:#x}; requires ext4, xfs, btrfs, f2fs, or zfs)"
                )));
        }

        // Create root directory if needed
        if !root.exists() {
            std::fs::create_dir_all(root)?;
            // Sync the parent directory so the root entry persists
            if let Some(parent) = root.parent() {
                let parent_fd = fs::open_dir_absolute(parent)?;
                fs::fsync_dir_fd(parent_fd.as_fd())?;
            }
        }

        let root_fd = fs::open_dir_absolute(root)?;

        // Refuse to overwrite an existing queue.
        let format_exists = fs::fstatat(root_fd.as_fd(), "FORMAT").is_ok();
        if format_exists {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "queue already initialized; use open() to access an existing queue",
            ));
        }

        // Create an exclusive initialization marker BEFORE any other state.
        // If .initializing already exists but FORMAT is absent, the previous
        // init was interrupted by a crash. Safe to clean up and retry since no FORMAT
        // means no queue identity was committed.
        let _init_marker = match fs::create_exclusive(root_fd.as_fd(), ".initializing", 0o600) {
            Ok(fd) => fd,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                // .initializing exists. If FORMAT is absent, this is a stale marker
                // from a crashed init. Safe to remove and retry.
                fs::unlinkat(root_fd.as_fd(), ".initializing")?;
                fs::create_exclusive(root_fd.as_fd(), ".initializing", 0o600).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "could not acquire init lock after cleaning stale marker",
                    )
                })?
            }
            Err(e) => return Err(e),
        };

        // Use RAII guard to clean up the init marker on any failure.
        struct InitGuard<'fd> {
            root_fd: BorrowedFd<'fd>,
            armed: bool,
        }
        impl Drop for InitGuard<'_> {
            fn drop(&mut self) {
                if self.armed {
                    // Remove the marker so a failed init can be retried
                    let _ = fs::unlinkat(self.root_fd, ".initializing");
                }
            }
        }
        let mut init_guard = InitGuard {
            root_fd: root_fd.as_fd(),
            armed: true,
        };

        // Create control/ early so we can hold the maintenance lock
        // with RAII (no mem::forget leak).
        fs::mkdirat_eexist_ok(root_fd.as_fd(), "control", 0o700)?;
        let control_fd = fs::open_directory(root_fd.as_fd(), "control")?;
        let lock_fd =
            fs::create_exclusive(control_fd.as_fd(), "maintenance.lock", 0o600).or_else(|e| {
                if e.kind() == io::ErrorKind::AlreadyExists {
                    fs::openat(control_fd.as_fd(), "maintenance.lock", libc::O_RDWR, 0o600)
                } else {
                    Err(e)
                }
            })?;
        let locked = fs::try_ofd_write_lock(lock_fd.as_fd())?;
        if !locked {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "another initializer or maintenance process holds the lock",
            ));
        }
        // Hold the maintenance lock for the duration of init by binding it.
        // It will be released when _init_lock goes out of scope at function end.
        let _init_lock = lock_fd;

        // Generate queue ID
        let queue_id = fs::random_128bit()?;
        let created_at = fs::clock_realtime_ns()?;

        let format_rec = FormatRecord::new(
            queue_id,
            created_at,
            opts.shard_count,
            opts.lease_bucket_width_ns,
            opts.delayed_bucket_width_ns,
            opts.terminal_bucket_width_ns,
            opts.max_payload_length,
        )
        .map_err(|e| io::Error::other(e.to_string()))?;

        // Create static directories
        for dir in [
            "control",
            "tmp",
            "ready",
            "leased",
            "delayed",
            "receipts",
            "dead",
            "quarantine",
        ] {
            fs::mkdirat_eexist_ok(root_fd.as_fd(), dir, 0o700)?;
        }
        // Sync root after directory creation
        fs::fsync_dir_fd(root_fd.as_fd())?;

        // Create static shard directories under ready/
        let ready_fd = fs::open_directory(root_fd.as_fd(), "ready")?;
        for i in 0..opts.shard_count {
            let shard_name = format!("{i:04x}");
            fs::mkdirat_eexist_ok(ready_fd.as_fd(), &shard_name, 0o700)?;
        }
        // Sync ready/ after shard creation
        fs::fsync_dir_fd(ready_fd.as_fd())?;
        // Sync root
        fs::fsync_dir_fd(root_fd.as_fd())?;

        // Create control lock files
        let control_fd = fs::open_directory(root_fd.as_fd(), "control")?;
        for lock_file in ["maintenance.lock", "wall-watermark.lock", "recovery.lock"] {
            let fd = fs::create_exclusive(control_fd.as_fd(), lock_file, 0o600).or_else(|e| {
                if e.kind() == io::ErrorKind::AlreadyExists {
                    fs::openat(control_fd.as_fd(), lock_file, 0o2, 0o600)
                } else {
                    Err(e)
                }
            })?;
            fs::fsync(fd.as_fd())?;
        }
        fs::fsync_dir_fd(control_fd.as_fd())?;
        fs::fsync_dir_fd(root_fd.as_fd())?;

        // Write initial wall watermark
        let wall_now = created_at;
        let wall_bucket =
            bucket_number(wall_now, opts.delayed_bucket_width_ns).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "zero bucket width in init")
            })?;
        let wm = WatermarkRecord {
            highest_observed_bucket: wall_bucket,
            sequence: 0,
        };
        let wm_bytes = wm.encode();
        // Write via temp file then rename
        // Use unique temp name to avoid collision on partial init rerun
        let wm_tmp_name = format!(
            ".wm.tmp.{}",
            steadq_names::hex_encode(&fs::random_128bit()?)
        );
        let wm_tmp = fs::create_exclusive(control_fd.as_fd(), &wm_tmp_name, 0o600)?;
        fs::write_all(wm_tmp.as_fd(), &wm_bytes)?;
        fs::fsync(wm_tmp.as_fd())?;
        fs::renameat(
            control_fd.as_fd(),
            &wm_tmp_name,
            control_fd.as_fd(),
            "wall-watermark",
        )?;
        fs::fsync_dir_fd(control_fd.as_fd())?;

        // Write FORMAT file
        let format_bytes = format_rec.encode();
        // Unique temp name for partial init recovery
        let fmt_tmp_name = format!(
            ".format.tmp.{}",
            steadq_names::hex_encode(&fs::random_128bit()?)
        );
        let fmt_tmp = fs::create_exclusive(root_fd.as_fd(), &fmt_tmp_name, 0o600)?;
        fs::write_all(fmt_tmp.as_fd(), &format_bytes)?;
        fs::fsync(fmt_tmp.as_fd())?;
        // Set FORMAT temp file to read-only before publication so the
        // published FORMAT is read-only even if the post-rename chmod is
        // skipped by an OutcomeUnknown return.
        fs::fchmodat(root_fd.as_fd(), &fmt_tmp_name, 0o400)?;
        // Publish FORMAT through the phase-aware executor so post-linearization
        // failures are classified correctly.
        match engine::move_verified_noreplace(
            root_fd.as_fd(),
            &fmt_tmp_name,
            root_fd.as_fd(),
            "FORMAT",
        ) {
            Ok(()) => {}
            Err(engine::MoveFailure::AlreadyExists) => {
                let _ = fs::unlinkat(root_fd.as_fd(), &fmt_tmp_name);
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "another initializer published FORMAT first",
                ));
            }
            Err(engine::MoveFailure::NotCommitted { phase, source }) => {
                let _ = fs::unlinkat(root_fd.as_fd(), &fmt_tmp_name);
                return Err(io::Error::other(format!(
                    "FORMAT publication failed at {phase:?}: {source}"
                )));
            }
            Err(engine::MoveFailure::OutcomeUnknown { phase, source }) => {
                // FORMAT may or may not be durable. The init marker stays so
                // a reopening process can detect the indeterminate state.
                return Err(io::Error::other(format!(
                    "FORMAT publication indeterminate at {phase:?}: {source}"
                )));
            }
            Err(engine::MoveFailure::SourceMissing) => {
                return Err(io::Error::other(
                    "FORMAT temp file vanished during publication",
                ));
            }
        }

        // FORMAT is now the linearization point. The executor has synced the
        // root directory. Remove the init marker and sync once more. These are
        // post-commit operations: FORMAT is published and the queue is usable,
        // so cleanup failures do not change the init outcome.
        init_guard.armed = false;
        let _ = fs::unlinkat(root_fd.as_fd(), ".initializing");
        let _ = fs::fsync_dir_fd(root_fd.as_fd());

        Ok(format_rec)
    }

    /// Open an existing queue.
    pub fn open(root: &Path, opts: &OpenOptions) -> Result<Self, Error> {
        // Open root first using descriptor-relative, no-symlink semantics
        let root_fd = fs::open_dir_absolute(root).map_err(Error::from)?;

        // Validate root is a directory
        let root_stat = fs::fstat(root_fd.as_fd()).map_err(Error::from)?;
        if root_stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(Error::QueueCorrupt("root path is not a directory".into()));
        }

        // Read FORMAT through descriptor-relative open, not pathname.
        // If FORMAT is absent, check whether an initialization was interrupted.
        let format_fd = match fs::openat(root_fd.as_fd(), "FORMAT", libc::O_RDONLY, 0) {
            Ok(fd) => fd,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                if fs::fstatat(root_fd.as_fd(), ".initializing").is_ok() {
                    return Err(Error::QueueCorrupt(
                        "queue initialization was interrupted; remove .initializing and retry init"
                            .into(),
                    ));
                }
                return Err(Error::QueueCorrupt("FORMAT file is missing".into()));
            }
            Err(e) => return Err(Error::from(e)),
        };
        let mut format_bytes = Vec::new();
        {
            let mut buf = [0u8; 4096];
            loop {
                match fs::read(format_fd.as_fd(), &mut buf) {
                    Ok(0) => break,
                    Ok(n) => format_bytes.extend_from_slice(&buf[..n]),
                    Err(e) => return Err(Error::from(e)),
                }
            }
        }
        let format_rec = FormatRecord::decode(&format_bytes).map_err(|e| match e {
            steadq_format::FormatError::UnsupportedVersion(_, _) => Error::UnsupportedFormat,
            _ => Error::QueueCorrupt(format!("FORMAT decode: {e}")),
        })?;

        // Validate retention bound: ceil(retention / terminal_width) + 2 <= 4096
        let probe_count = ceiling_bucket(
            opts.receipt_retention_ns,
            format_rec.terminal_bucket_width_ns(),
        )
        .ok_or_else(|| Error::QueueCorrupt("invalid terminal bucket width".into()))?
        .saturating_add(2);
        if probe_count > 4096 {
            return Err(Error::InvalidInput(
                "receipt retention exceeds duplicate-ack probe bound".into(),
            ));
        }

        // Check filesystem type. Keep the observation even when validation is
        // relaxed because publication performance differs materially by backend.
        // fs_type_magic normalizes f_type, which is signed on glibc and
        // unsigned on musl.
        let filesystem_type =
            classify_filesystem_type(fs::fs_type_magic(root), opts.allow_unsupported_fs)?;

        // Require all state directories to exist and be on the same device.
        for state_dir in &[
            "control",
            "ready",
            "leased",
            "delayed",
            "receipts",
            "dead",
            "quarantine",
            "tmp",
        ] {
            match fs::fstatat(root_fd.as_fd(), state_dir) {
                Ok(stat) => {
                    if stat.st_dev != root_stat.st_dev {
                        return Err(Error::QueueCorrupt(format!(
                            "state directory '{state_dir}' is on a different device than root"
                        )));
                    }
                    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
                        return Err(Error::QueueCorrupt(format!(
                            "state path '{state_dir}' is not a directory"
                        )));
                    }
                }
                Err(_) => {
                    return Err(Error::QueueCorrupt(format!(
                        "required state directory '{state_dir}' is missing"
                    )));
                }
            }
        }

        // Read boot ID
        let boot_id = fs::read_boot_id().map_err(Error::from)?;
        let boot_id_bin = steadq_names::boot_id_bytes(&boot_id)
            .ok_or_else(|| Error::InvalidInput("invalid boot_id format".into()))?;

        // Generate worker nonce
        let worker_nonce = fs::random_128bit().map_err(Error::from)?;

        // Acquire shared maintenance lock
        let maint_fd = fs::openat(root_fd.as_fd(), "control/maintenance.lock", 0o0, 0o600)
            .map_err(Error::from)?;
        let locked = fs::try_ofd_read_lock(maint_fd.as_fd()).map_err(Error::from)?;
        if !locked {
            return Err(Error::MaintenanceBusy);
        }
        let recovery_cursor =
            crate::recovery::load_recovery_cursor(root_fd.as_fd(), format_rec.queue_id())?;
        let publication_mode = filesystem_type.and_then(preferred_publication_mode);
        Ok(Queue {
            root_fd,
            root_path: root.to_path_buf(),
            format: format_rec,
            boot_id,
            boot_id_bytes: boot_id_bin,
            poisoned: false,
            scan_round: 0,
            ready_shard_hint: None,
            worker_nonce,
            options: opts.clone(),
            _maint_lock_fd: Some(maint_fd),
            recovery_cursor,
            cached_wall_floor: None,
            cached_watermark_fd: std::cell::RefCell::new(None),
            known_dirs: std::cell::RefCell::new(std::collections::HashSet::new()),
            cached_dest_fd: None,
            publication_mode,
            deferred_dir_sync: opts.deferred_dir_sync,
            dirty: std::cell::RefCell::new(engine::DirtySet::new()),
            ready_watch: None,
            ready_watch_attempted: false,
        })
    }

    pub fn format(&self) -> &FormatRecord {
        &self.format
    }

    pub fn queue_id(&self) -> &[u8; 16] {
        self.format.queue_id()
    }

    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    pub fn root_fd(&self) -> BorrowedFd<'_> {
        self.root_fd.as_fd()
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    fn check_not_poisoned(&self) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::QueuePoisoned("handle is poisoned".into()));
        }
        Ok(())
    }

    fn poison(&mut self) {
        self.poisoned = true;
    }

    pub(crate) fn layout(&self) -> layout::Layout<'_> {
        layout::Layout::new(
            self.format.queue_id(),
            self.format.shard_count(),
            self.format.lease_bucket_width_ns(),
            self.format.delayed_bucket_width_ns(),
            self.format.terminal_bucket_width_ns(),
            &self.boot_id,
        )
    }
}

/// Open a relative path from a directory fd.
pub(crate) fn open_relative(root_fd: BorrowedFd<'_>, relative: &str) -> io::Result<OwnedFd> {
    let relative = fs::ValidatedRelativePath::new(relative)?;
    fs::open_directory_beneath(root_fd, relative)
}

/// Input for an enqueue operation.
#[derive(Clone, Debug, Default)]
pub struct EnqueueInput {
    pub maximum_attempts: u32,
    pub content_type: String,
    pub metadata: std::collections::BTreeMap<String, steadq_format::cbor::MetadataValue>,
    pub producer_id: Option<String>,
    pub trace_context: Option<Vec<u8>>,
    pub initial_not_before: Option<u64>,
    pub payload: Vec<u8>,
}

#[cfg(test)]
mod tests;
