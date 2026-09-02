// Linux syscall substrate for SteadQ/1.
// Confines all unsafe code to this module.

#![deny(clippy::undocumented_unsafe_blocks)]

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};
use std::path::Path;
use std::ptr::NonNull;

const MAX_COMPONENT_BYTES: usize = 255;
const MAX_RELATIVE_PATH_BYTES: usize = 4095;
const INLINE_C_PATH_BYTES: usize = MAX_COMPONENT_BYTES + 1;

const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const RESOLVER_RESOLVE_FLAGS: u64 = RESOLVE_NO_MAGICLINKS + RESOLVE_NO_SYMLINKS + RESOLVE_BENEATH;

fn resolver_open_flags() -> i32 {
    libc::O_DIRECTORY
        .checked_add(libc::O_CLOEXEC)
        .expect("Linux open flags fit i32")
}

/// A relative path whose components are safe to resolve beneath a directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedRelativePath<'a> {
    path: &'a str,
}

impl<'a> ValidatedRelativePath<'a> {
    pub fn new(path: &'a str) -> io::Result<Self> {
        validate_relative_path(path)
    }

    pub fn as_str(self) -> &'a str {
        self.path
    }

    pub fn components(self) -> impl Iterator<Item = &'a str> {
        self.path.split('/')
    }
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

// ---------- Fault injection ----------

/// Fault injection control for deterministic failure testing.
///
/// State is thread-local so parallel tests do not interfere with each other.
/// Idle threads pay only a TLS lookup that finds an empty map.
pub mod fault {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::io;
    use std::os::fd::RawFd;

    #[derive(Clone, Copy, Debug)]
    struct Fault {
        current: u64,
        target: u64,
        errno: i32,
    }

    struct State {
        faults: HashMap<String, Fault>,
        counts: HashMap<String, u64>,
        fd_identities: HashMap<String, Vec<(u64, u64)>>,
        readdir_rotation: usize,
        readdir_reversed: bool,
        realtime_ns: Option<u64>,
        boottime_ns: Option<u64>,
        pinned_realtime_ns: Option<u64>,
    }

    impl State {
        fn new() -> Self {
            State {
                faults: HashMap::new(),
                counts: HashMap::new(),
                fd_identities: HashMap::new(),
                readdir_rotation: 0,
                readdir_reversed: false,
                realtime_ns: None,
                boottime_ns: None,
                pinned_realtime_ns: None,
            }
        }
    }

    thread_local! {
        static STATE: RefCell<State> = RefCell::new(State::new());
    }

    /// Clear all pending faults and call counters on this thread.
    pub fn reset() {
        STATE.with(|s| {
            let mut s = s.borrow_mut();
            s.faults.clear();
            s.counts.clear();
            s.fd_identities.clear();
            s.readdir_rotation = 0;
            s.readdir_reversed = false;
            s.realtime_ns = s.pinned_realtime_ns;
            s.boottime_ns = None;
        });
    }

    /// Pin the realtime clock for the life of this thread. `reset()` restores
    /// the pin instead of the wall clock, so a fixture's frozen time survives
    /// every fault reset in the test. Fixtures pin so a bucket boundary cannot
    /// trigger a wall-watermark advance that consumes a count-based fault
    /// before the operation under test reaches it.
    pub fn pin_clock_realtime_ns(unix_ns: u64) {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.pinned_realtime_ns = Some(unix_ns);
            state.realtime_ns = Some(unix_ns);
        });
    }

    /// Return a fixed value from subsequent realtime clock reads on this thread.
    pub fn set_clock_realtime_ns(unix_ns: u64) {
        STATE.with(|state| state.borrow_mut().realtime_ns = Some(unix_ns));
    }

    pub(crate) fn clock_realtime_ns() -> Option<u64> {
        STATE.with(|state| state.borrow().realtime_ns)
    }

    /// Return a fixed value from subsequent boottime clock reads on this thread.
    pub fn set_clock_boottime_ns(boottime_ns: u64) {
        STATE.with(|state| state.borrow_mut().boottime_ns = Some(boottime_ns));
    }

    pub(crate) fn clock_boottime_ns() -> Option<u64> {
        STATE.with(|state| state.borrow().boottime_ns)
    }

    /// Permute complete directory enumerations on this thread.
    pub fn permute_readdir(rotation: usize, reversed: bool) {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.readdir_rotation = rotation;
            state.readdir_reversed = reversed;
        });
    }

    pub(crate) fn permute_directory_entries<T>(entries: &mut [T]) {
        STATE.with(|state| {
            let state = state.borrow();
            if entries.is_empty() {
                return;
            }
            let rotation = state.readdir_rotation % entries.len();
            entries.rotate_left(rotation);
            if state.readdir_reversed {
                entries.reverse();
            }
        });
    }

    /// Fail the Nth (1-indexed) call to `func_name` with EIO.
    pub fn inject(func_name: &str, at_count: u64) {
        inject_errno(func_name, at_count, libc::EIO);
    }

    /// Fail the Nth (1-indexed) call to `func_name` with the given errno.
    pub fn inject_errno(func_name: &str, at_count: u64, errno: i32) {
        assert!(at_count >= 1, "fault inject count is 1-indexed");
        STATE.with(|s| {
            s.borrow_mut().faults.insert(
                func_name.to_string(),
                Fault {
                    current: 0,
                    target: at_count,
                    errno,
                },
            );
        });
    }

    /// Number of times `func_name` has been checked since the last reset.
    pub fn call_count(func_name: &str) -> u64 {
        STATE.with(|s| *s.borrow().counts.get(func_name).unwrap_or(&0))
    }

    /// Ordered device/inode identities recorded for fd-bearing fault points.
    pub fn fd_identities(func_name: &str) -> Vec<(u64, u64)> {
        STATE.with(|state| {
            state
                .borrow()
                .fd_identities
                .get(func_name)
                .cloned()
                .unwrap_or_default()
        })
    }

    pub(crate) fn record_fd_identity(func_name: &str, fd: RawFd) -> io::Result<()> {
        STATE.with(|state| {
            if state.borrow().faults.is_empty() {
                return Ok(());
            }

            // SAFETY: Linux `stat` contains only integer fields and may be zero-initialized.
            let mut statbuf: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: `statbuf` points to writable storage for one `libc::stat`,
            // and the caller supplies an open descriptor for the duration of
            // this synchronous instrumentation call.
            if unsafe { libc::fstat(fd, &mut statbuf) } < 0 {
                return Err(io::Error::last_os_error());
            }
            state
                .borrow_mut()
                .fd_identities
                .entry(func_name.to_string())
                .or_default()
                .push((statbuf.st_dev as u64, statbuf.st_ino as u64));
            Ok(())
        })
    }

    /// Called by instrumented functions. Returns an error when a fault fires.
    #[inline]
    pub fn check(func_name: &str) -> Option<io::Error> {
        STATE.with(|s| {
            let mut s = s.borrow_mut();
            if s.faults.is_empty() {
                return None;
            }
            *s.counts.entry(func_name.to_string()).or_insert(0) += 1;
            if let Some(entry) = s.faults.get_mut(func_name) {
                entry.current += 1;
                if entry.current == entry.target {
                    let errno = entry.errno;
                    s.faults.remove(func_name);
                    return Some(io::Error::from_raw_os_error(errno));
                }
            }
            None
        })
    }
}

macro_rules! fault_check {
    ($name:expr) => {
        if let Some(e) = $crate::fault::check($name) {
            return Err(e);
        }
    };
}

pub mod inotify;

/// Open or create a file with O_TMPFILE.
pub fn open_tmpfile(dir_fd: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    fault_check!("open_tmpfile");
    // libc::O_TMPFILE includes O_DIRECTORY on all architectures.
    let o_tmpfile = libc::O_TMPFILE;
    // SAFETY: the C string is NUL-terminated and `dir_fd` remains live for the call.
    let fd = unsafe {
        libc::openat(
            dir_fd.as_raw_fd(),
            c".".as_ptr(),
            o_tmpfile | libc::O_RDWR | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a nonnegative `openat` result is a newly owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// A NUL-terminated syscall path. Canonical SteadQ names stay inline; unusually
/// long paths fall back to the heap.
#[allow(clippy::large_enum_variant)] // Boxing the common case would restore the allocation avoided here.
enum CPath {
    Inline([u8; INLINE_C_PATH_BYTES]),
    Heap(CString),
}

impl CPath {
    fn from_bytes(bytes: &[u8], nul_error: &'static str) -> io::Result<Self> {
        if bytes.contains(&0) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, nul_error));
        }
        if bytes.len() < INLINE_C_PATH_BYTES {
            let mut inline = [0; INLINE_C_PATH_BYTES];
            inline[..bytes.len()].copy_from_slice(bytes);
            Ok(Self::Inline(inline))
        } else {
            // The explicit NUL check above makes construction infallible.
            Ok(Self::Heap(
                CString::new(bytes).expect("NUL already rejected"),
            ))
        }
    }

    fn as_ptr(&self) -> *const libc::c_char {
        match self {
            Self::Inline(bytes) => bytes.as_ptr().cast(),
            Self::Heap(path) => path.as_ptr(),
        }
    }
}

/// Convert a name string to a NUL-terminated syscall path.
fn cstr_from_name(name: &str) -> io::Result<CPath> {
    CPath::from_bytes(name.as_bytes(), "path component contains NUL byte")
}

/// Convert a byte slice (OsStr on Linux) to a NUL-terminated syscall path.
pub(crate) fn cstr_from_bytes(bytes: &[u8]) -> io::Result<CPath> {
    CPath::from_bytes(bytes, "path contains NUL byte")
}

fn proc_self_fd_path(fd: BorrowedFd<'_>) -> [u8; 32] {
    proc_self_fd_path_raw(fd.as_raw_fd() as u32)
}

fn proc_self_fd_path_raw(value: u32) -> [u8; 32] {
    const PREFIX: &[u8] = b"/proc/self/fd/";
    let mut path = [0; 32];
    path[..PREFIX.len()].copy_from_slice(PREFIX);

    let mut divisor = 1_u32;
    while value / divisor >= 10 {
        divisor *= 10;
    }
    let mut offset = PREFIX.len();
    loop {
        path[offset] = b'0' + ((value / divisor) % 10) as u8;
        offset += 1;
        if divisor == 1 {
            break;
        }
        divisor /= 10;
    }
    path
}

/// Open a directory for reading.
pub fn open_directory(dir_fd: BorrowedFd<'_>, name: &str) -> io::Result<OwnedFd> {
    fault_check!("open_directory");
    // O_NOFOLLOW: state directories must not be symlinks.
    let c_name = cstr_from_name(name)?;
    // SAFETY: `c_name` is NUL-terminated and `dir_fd` remains live for the call.
    let fd = unsafe {
        libc::openat(
            dir_fd.as_raw_fd(),
            c_name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a nonnegative `openat` result is a newly owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Open a directory path while the kernel enforces confinement beneath `root_fd`.
pub fn open_directory_beneath(
    root_fd: BorrowedFd<'_>,
    relative: ValidatedRelativePath<'_>,
) -> io::Result<OwnedFd> {
    fault_check!("openat2_beneath");
    let path = cstr_from_name(relative.as_str())?;
    let how = OpenHow {
        flags: resolver_open_flags() as u64,
        mode: 0,
        resolve: RESOLVER_RESOLVE_FLAGS,
    };
    // SAFETY: `path` is NUL-terminated, `how` has the kernel open_how layout,
    // and both pointers remain valid for the duration of the syscall.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root_fd.as_raw_fd(),
            path.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        ) as libc::c_int
    };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a nonnegative openat2 result is a newly owned file descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Open a path relative to a directory fd with given flags.
pub fn openat(dir_fd: BorrowedFd<'_>, name: &str, flags: i32, mode: u32) -> io::Result<OwnedFd> {
    fault_check!("openat");
    let c_name = cstr_from_name(name)?;
    // SAFETY: `c_name` is NUL-terminated and `dir_fd` remains live for the call.
    let fd = unsafe { libc::openat(dir_fd.as_raw_fd(), c_name.as_ptr(), flags, mode) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a nonnegative `openat` result is a newly owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Create a directory.
pub fn mkdirat(dir_fd: BorrowedFd<'_>, name: &str, mode: u32) -> io::Result<()> {
    fault_check!("mkdirat");
    let c_name = cstr_from_name(name)?;
    // SAFETY: `c_name` is NUL-terminated and `dir_fd` remains live for the call.
    let rc = unsafe { libc::mkdirat(dir_fd.as_raw_fd(), c_name.as_ptr(), mode) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Create a directory, treating EEXIST as Ok.
/// Returns true if the directory was newly created, false if it already existed.
pub fn mkdirat_eexist_ok(dir_fd: BorrowedFd<'_>, name: &str, mode: u32) -> io::Result<bool> {
    match mkdirat(dir_fd, name, mode) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e),
    }
}

/// fsync a file descriptor.
pub fn fsync(fd: BorrowedFd<'_>) -> io::Result<()> {
    fault_check!("fsync");
    // SAFETY: `fd` remains live for the synchronous syscall.
    let rc = unsafe { libc::fsync(fd.as_raw_fd()) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// fsync a directory by opening it read-only and syncing.
pub fn fsync_dir(dir_fd: BorrowedFd<'_>, name: &str) -> io::Result<()> {
    fault_check!("fsync_dir");
    let fd = open_directory(dir_fd, name)?;
    fsync(fd.as_fd())
}

/// fsync a directory by its already-open fd.
pub fn fsync_dir_fd(fd: BorrowedFd<'_>) -> io::Result<()> {
    fault::record_fd_identity("fsync_dir_fd", fd.as_raw_fd())?;
    fault_check!("fsync_dir_fd");
    fsync(fd)
}

/// Rename with RENAME_NOREPLACE.
pub fn renameat2_noreplace(
    old_dir_fd: BorrowedFd<'_>,
    old_name: &str,
    new_dir_fd: BorrowedFd<'_>,
    new_name: &str,
) -> io::Result<()> {
    fault_check!("renameat2_noreplace");
    const RENAME_NOREPLACE: u32 = 1 << 0;
    let c_old = cstr_from_name(old_name)?;
    let c_new = cstr_from_name(new_name)?;
    // SAFETY: both names are NUL-terminated and both directory borrows remain live.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            old_dir_fd.as_raw_fd(),
            c_old.as_ptr(),
            new_dir_fd.as_raw_fd(),
            c_new.as_ptr(),
            RENAME_NOREPLACE,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Plain rename (for receipt compaction).
pub fn renameat(
    old_dir_fd: BorrowedFd<'_>,
    old_name: &str,
    new_dir_fd: BorrowedFd<'_>,
    new_name: &str,
) -> io::Result<()> {
    fault_check!("renameat");
    let c_old = cstr_from_name(old_name)?;
    let c_new = cstr_from_name(new_name)?;
    // SAFETY: both names are NUL-terminated and both directory borrows remain live.
    let rc = unsafe {
        libc::renameat(
            old_dir_fd.as_raw_fd(),
            c_old.as_ptr(),
            new_dir_fd.as_raw_fd(),
            c_new.as_ptr(),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// linkat with AT_EMPTY_PATH for O_TMPFILE publication.
pub fn linkat_empty_path(
    fd: BorrowedFd<'_>,
    dest_dir_fd: BorrowedFd<'_>,
    dest_name: &str,
) -> io::Result<()> {
    fault_check!("linkat_empty_path");
    const AT_EMPTY_PATH: i32 = 0x1000;
    let c_dest = cstr_from_name(dest_name)?;
    // SAFETY: both names are NUL-terminated and both descriptor borrows remain live.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_linkat,
            fd.as_raw_fd(),
            c"".as_ptr(),
            dest_dir_fd.as_raw_fd(),
            c_dest.as_ptr(),
            AT_EMPTY_PATH,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// linkat via /proc/self/fd for unprivileged O_TMPFILE publication.
pub fn linkat_proc_self_fd(
    fd: BorrowedFd<'_>,
    dest_dir_fd: BorrowedFd<'_>,
    dest_name: &str,
) -> io::Result<()> {
    fault_check!("linkat_proc_self_fd");
    const AT_SYMLINK_FOLLOW: i32 = 0x400;
    let proc_path = proc_self_fd_path(fd);
    let c_dest = cstr_from_name(dest_name)?;
    // SAFETY: both paths are NUL-terminated and both descriptor borrows remain live.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_linkat,
            libc::AT_FDCWD,
            proc_path.as_ptr().cast::<libc::c_char>(),
            dest_dir_fd.as_raw_fd(),
            c_dest.as_ptr(),
            AT_SYMLINK_FOLLOW,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// unlinkat - remove a file.
pub fn unlinkat(dir_fd: BorrowedFd<'_>, name: &str) -> io::Result<()> {
    fault_check!("unlinkat");
    let c_name = cstr_from_name(name)?;
    // SAFETY: `c_name` is NUL-terminated and `dir_fd` remains live for the call.
    let rc = unsafe { libc::unlinkat(dir_fd.as_raw_fd(), c_name.as_ptr(), 0) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Remove a directory (must be empty).
pub fn unlinkat_dir(dir_fd: BorrowedFd<'_>, name: &str) -> io::Result<()> {
    fault_check!("unlinkat_dir");
    const AT_REMOVEDIR: i32 = 0x200;
    let c_name = cstr_from_name(name)?;
    // SAFETY: `c_name` is NUL-terminated and `dir_fd` remains live for the call.
    let rc = unsafe { libc::unlinkat(dir_fd.as_raw_fd(), c_name.as_ptr(), AT_REMOVEDIR) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// stat a file relative to a directory fd using AT_SYMLINK_NOFOLLOW.
pub fn fstatat(dir_fd: BorrowedFd<'_>, name: &str) -> io::Result<libc::stat> {
    fault_check!("fstatat");
    let c_name = cstr_from_name(name)?;
    // SAFETY: Linux `stat` contains only integer fields and may be zero-initialized.
    let mut statbuf: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `c_name` is NUL-terminated, `statbuf` is writable, and `dir_fd` is live.
    let rc = unsafe {
        libc::fstatat(
            dir_fd.as_raw_fd(),
            c_name.as_ptr(),
            &mut statbuf,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(statbuf)
}

/// fstat on an already-open fd.
pub fn fstat(fd: BorrowedFd<'_>) -> io::Result<libc::stat> {
    fault_check!("fstat");
    // SAFETY: Linux `stat` contains only integer fields and may be zero-initialized.
    let mut statbuf: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `statbuf` is writable and `fd` remains live for the call.
    let rc = unsafe { libc::fstat(fd.as_raw_fd(), &mut statbuf) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(statbuf)
}

/// Get filesystem stats using OsStrExt for byte-safe paths.
pub fn statfs(path: &Path) -> io::Result<libc::statfs> {
    let c_path = cstr_from_bytes(path.as_os_str().as_bytes())?;
    // SAFETY: Linux `statfs` contains only integer fields and may be zero-initialized.
    let mut statbuf: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c_path` is NUL-terminated and `statbuf` is writable for the call.
    let rc = unsafe { libc::statfs(c_path.as_ptr(), &mut statbuf) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(statbuf)
}

/// Read the boot ID from /proc/sys/kernel/random/boot_id.
pub fn read_boot_id() -> io::Result<String> {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map(|s| s.trim().to_string())
}

/// CLOCK_BOOTTIME in nanoseconds.
pub fn clock_boottime_ns() -> io::Result<u64> {
    fault_check!("clock_boottime_ns");
    if let Some(ns) = fault::clock_boottime_ns() {
        return Ok(ns);
    }
    // SAFETY: Linux `timespec` contains integer fields and may be zero-initialized.
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: `ts` points to writable storage for one `timespec`.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64)
}

/// CLOCK_REALTIME in nanoseconds.
pub fn clock_realtime_ns() -> io::Result<u64> {
    fault_check!("clock_realtime_ns");
    if let Some(unix_ns) = fault::clock_realtime_ns() {
        return Ok(unix_ns);
    }
    // SAFETY: Linux `timespec` contains integer fields and may be zero-initialized.
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: `ts` points to writable storage for one `timespec`.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    timespec_to_unix_ns(&ts)
}

/// Convert a CLOCK_REALTIME reading to Unix nanoseconds, rejecting any
/// time before the Unix epoch.
fn timespec_to_unix_ns(ts: &libc::timespec) -> io::Result<u64> {
    if ts.tv_sec < 0 || ts.tv_nsec < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "clock before epoch",
        ));
    }
    Ok(ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64)
}

/// CLOCK_MONOTONIC in nanoseconds (for budget enforcement).
pub fn clock_monotonic_ns() -> io::Result<u64> {
    fault_check!("clock_monotonic_ns");
    // SAFETY: Linux `timespec` contains integer fields and may be zero-initialized.
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: `ts` points to writable storage for one `timespec`.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64)
}

/// Generate random bytes from the OS crypto source.
/// Loops until the entire buffer is filled. Handles short reads, EINTR,
/// and EAGAIN. Returns an error (not zero data) on any failure.
fn is_eagain(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::EAGAIN)
}

fn is_interrupted(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::Interrupted
}

pub fn get_random(bytes: usize) -> io::Result<Vec<u8>> {
    fault_check!("get_random");
    if bytes == 0 {
        return Ok(Vec::new());
    }
    let mut buf = vec![0u8; bytes];
    let mut filled = 0usize;
    loop {
        // SAFETY: the remaining slice is writable for its reported length.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_getrandom,
                buf[filled..].as_mut_ptr(),
                bytes - filled,
                0,
            )
        };
        if rc < 0 {
            let e = io::Error::last_os_error();
            if is_interrupted(&e) {
                continue;
            }
            // Defensive: EAGAIN does not occur with flags=0.
            if is_eagain(&e) {
                continue;
            }
            return Err(e);
        }
        let n = rc as usize;
        if n == 0 {
            // A zero-byte return is anomalous; treat as an error.
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "getrandom returned zero bytes",
            ));
        }
        filled += n;
        if filled >= bytes {
            break;
        }
    }
    Ok(buf)
}

/// Generate a random 128-bit value.
pub fn random_128bit() -> io::Result<[u8; 16]> {
    let bytes = get_random(16)?;
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// pwrite to a file descriptor at a given offset.
pub fn pwrite(fd: BorrowedFd<'_>, buf: &[u8], offset: u64) -> io::Result<usize> {
    fault_check!("pwrite");
    // SAFETY: `buf` is readable for its length and `fd` remains live for the call.
    let rc = unsafe {
        libc::pwrite(
            fd.as_raw_fd(),
            buf.as_ptr() as *const _,
            buf.len(),
            offset as i64,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(rc as usize)
}

/// Write all bytes, retrying on partial writes; a zero-byte write is an error.
pub fn write_all(fd: BorrowedFd<'_>, buf: &[u8]) -> io::Result<()> {
    if buf.is_empty() {
        return Ok(());
    }
    fault_check!("write_all");
    let mut written = 0;
    while written < buf.len() {
        let remaining = &buf[written..];
        // SAFETY: `remaining` is readable for its length and `fd` remains live.
        let rc = unsafe {
            libc::write(
                fd.as_raw_fd(),
                remaining.as_ptr() as *const _,
                remaining.len(),
            )
        };
        if rc < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if rc == 0 {
            // write returning 0 signals an error (e.g. full filesystem, broken pipe).
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "write returned zero bytes (no progress)",
            ));
        }
        written += rc as usize;
    }
    Ok(())
}

/// Write multiple buffers in a single syscall using writev(2).
pub fn writev_all(fd: BorrowedFd<'_>, bufs: &[&[u8]]) -> io::Result<()> {
    if bufs.iter().all(|b| b.is_empty()) {
        return Ok(());
    }
    fault_check!("write_all");

    let mut iovs: Vec<libc::iovec> = bufs
        .iter()
        .filter(|b| !b.is_empty())
        .map(|b| libc::iovec {
            iov_base: b.as_ptr() as *mut _,
            iov_len: b.len(),
        })
        .collect();

    while !iovs.is_empty() {
        // SAFETY: `iovs` contains valid pointers and lengths from live slices,
        // and `fd` is live.
        let rc = unsafe { libc::writev(fd.as_raw_fd(), iovs.as_ptr(), iovs.len() as i32) };
        if rc < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }

        let mut written = rc as usize;
        while written > 0 && !iovs.is_empty() {
            if written >= iovs[0].iov_len {
                written -= iovs[0].iov_len;
                iovs.remove(0);
            } else {
                // SAFETY: advancing the base pointer by `written` bytes within the original buffer.
                iovs[0].iov_base = unsafe { (iovs[0].iov_base as *mut u8).add(written) as *mut _ };
                iovs[0].iov_len -= written;
                written = 0;
            }
        }
    }
    Ok(())
}

/// Write all bytes at `offset`, retrying on partial writes; a zero-byte write is an error.
pub fn pwrite_all(fd: BorrowedFd<'_>, buf: &[u8], offset: u64) -> io::Result<()> {
    let mut written = 0;
    let mut current_offset = offset;
    while written < buf.len() {
        let n = pwrite(fd, &buf[written..], current_offset)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "pwrite returned zero bytes (no progress)",
            ));
        }
        written += n;
        current_offset += n as u64;
    }
    Ok(())
}

/// Read from a file descriptor.
pub fn read(fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        // SAFETY: `buf` is writable for its length and `fd` remains live for the call.
        let rc = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr() as *mut _, buf.len()) };
        if rc < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        return Ok(rc as usize);
    }
}

/// Read at a specific offset using pread.
pub fn pread(fd: BorrowedFd<'_>, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    fault_check!("pread");
    loop {
        // SAFETY: `buf` is writable for its length and `fd` remains live for the call.
        let rc = unsafe {
            libc::pread(
                fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut _,
                buf.len(),
                offset as i64,
            )
        };
        if rc < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        return Ok(rc as usize);
    }
}

/// Read exactly `buf.len()` bytes at `offset`, or return an error.
pub fn pread_exact(fd: BorrowedFd<'_>, buf: &mut [u8], offset: u64) -> io::Result<()> {
    let mut filled = 0;
    let mut cur = offset;
    while filled < buf.len() {
        let n = pread(fd, &mut buf[filled..], cur)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "pread hit EOF before filling buffer",
            ));
        }
        filled += n;
        cur += n as u64;
    }
    Ok(())
}

/// Open a directory path (absolute) and return an OwnedFd.
pub fn open_dir_absolute(path: &Path) -> io::Result<OwnedFd> {
    // O_NOFOLLOW: the queue root must not be a symlink.
    let c_path = cstr_from_bytes(path.as_os_str().as_bytes())?;
    // SAFETY: `c_path` is NUL-terminated and remains live for the call.
    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a nonnegative `open` result is a newly owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Create a file with O_CREAT | O_EXCL | O_NOFOLLOW.
pub fn create_exclusive(dir_fd: BorrowedFd<'_>, name: &str, mode: u32) -> io::Result<OwnedFd> {
    openat(
        dir_fd,
        name,
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        mode,
    )
}

/// Try a nonblocking exclusive OFD lock on a file.
/// Returns Ok(true) if acquired, Ok(false) if contended.
pub fn try_ofd_write_lock(fd: BorrowedFd<'_>) -> io::Result<bool> {
    fault_check!("try_ofd_write_lock");
    // SAFETY: Linux `flock` contains scalar fields and may be zero-initialized.
    let mut flock: libc::flock = unsafe { std::mem::zeroed() };
    flock.l_type = libc::F_WRLCK as i16;
    flock.l_whence = libc::SEEK_SET as i16;
    flock.l_start = 0;
    flock.l_len = 0;
    // SAFETY: `flock` is readable and `fd` remains live for the call.
    let rc = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_OFD_SETLK, &flock) };
    if rc < 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::WouldBlock || e.raw_os_error() == Some(libc::EAGAIN) {
            return Ok(false);
        }
        return Err(e);
    }
    Ok(true)
}

/// Try a nonblocking shared OFD lock on a file.
pub fn try_ofd_read_lock(fd: BorrowedFd<'_>) -> io::Result<bool> {
    fault_check!("try_ofd_read_lock");
    // SAFETY: Linux `flock` contains scalar fields and may be zero-initialized.
    let mut flock: libc::flock = unsafe { std::mem::zeroed() };
    flock.l_type = libc::F_RDLCK as i16;
    flock.l_whence = libc::SEEK_SET as i16;
    flock.l_start = 0;
    flock.l_len = 0;
    // SAFETY: `flock` is readable and `fd` remains live for the call.
    let rc = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_OFD_SETLK, &flock) };
    if rc < 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::WouldBlock || e.raw_os_error() == Some(libc::EAGAIN) {
            return Ok(false);
        }
        return Err(e);
    }
    Ok(true)
}

/// Byte-preserving directory entry name.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct DirEntryName(Vec<u8>);

impl DirEntryName {
    /// Returns the exact bytes supplied by the directory stream.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the name when it is valid UTF-8.
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    /// Returns the name only when it belongs to the protocol's ASCII alphabet.
    pub fn as_ascii_str(&self) -> Option<&str> {
        if self.0.is_ascii() {
            self.as_str()
        } else {
            None
        }
    }
}

impl std::fmt::Debug for DirEntryName {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "b\"")?;
        for byte in &self.0 {
            for escaped in std::ascii::escape_default(*byte) {
                write!(formatter, "{}", char::from(escaped))?;
            }
        }
        write!(formatter, "\"")
    }
}

/// Exact protocol-visible work completed by a directory enumeration.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DirectoryEnumerationProgress {
    /// Non-dot entries returned by `readdir`.
    pub entries_read: usize,
    /// Raw name bytes across those entries.
    pub name_bytes_read: usize,
}

/// A complete bounded enumeration and its work accounting.
#[derive(Debug)]
pub struct DirectoryEnumeration {
    pub entries: Vec<DirEntryName>,
    pub progress: DirectoryEnumerationProgress,
}

#[derive(Debug)]
pub enum DirectoryEnumerationError {
    Cancelled,
    CancellationCheck(io::Error),
    Io(io::Error),
}

#[derive(Debug)]
pub enum DirectoryEnumerationProgressError {
    Cancelled(DirectoryEnumerationProgress),
    CancellationCheck {
        error: io::Error,
        progress: DirectoryEnumerationProgress,
    },
    Io {
        error: io::Error,
        progress: DirectoryEnumerationProgress,
    },
}

impl std::fmt::Display for DirectoryEnumerationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => write!(formatter, "directory enumeration cancelled"),
            Self::CancellationCheck(error) => {
                write!(formatter, "directory cancellation check failed: {error}")
            }
            Self::Io(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for DirectoryEnumerationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Cancelled => None,
            Self::CancellationCheck(error) | Self::Io(error) => Some(error),
        }
    }
}

impl DirectoryEnumerationError {
    fn into_io_error(self) -> io::Error {
        match self {
            Self::Cancelled => io::Error::new(
                io::ErrorKind::Interrupted,
                "directory enumeration cancelled unexpectedly",
            ),
            Self::CancellationCheck(error) | Self::Io(error) => error,
        }
    }
}

impl std::fmt::Display for DirectoryEnumerationProgressError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled(_) => write!(formatter, "directory enumeration cancelled"),
            Self::CancellationCheck { error, .. } => {
                write!(formatter, "directory cancellation check failed: {error}")
            }
            Self::Io { error, .. } => error.fmt(formatter),
        }
    }
}

impl std::error::Error for DirectoryEnumerationProgressError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Cancelled(_) => None,
            Self::CancellationCheck { error, .. } | Self::Io { error, .. } => Some(error),
        }
    }
}

impl DirectoryEnumerationProgressError {
    pub fn progress(&self) -> DirectoryEnumerationProgress {
        match self {
            Self::Cancelled(progress)
            | Self::CancellationCheck { progress, .. }
            | Self::Io { progress, .. } => *progress,
        }
    }

    fn into_legacy(self) -> DirectoryEnumerationError {
        match self {
            Self::Cancelled(_) => DirectoryEnumerationError::Cancelled,
            Self::CancellationCheck { error, .. } => {
                DirectoryEnumerationError::CancellationCheck(error)
            }
            Self::Io { error, .. } => DirectoryEnumerationError::Io(error),
        }
    }
}

/// Streaming, byte-preserving directory enumeration.
pub struct DirectoryStream(NonNull<libc::DIR>);

impl DirectoryStream {
    fn from_owned(fd: OwnedFd) -> io::Result<Self> {
        let raw_fd = fd.into_raw_fd();
        // SAFETY: `raw_fd` is a live directory descriptor. `fdopendir`
        // takes ownership on success and leaves ownership with the caller on failure.
        let dir = unsafe { libc::fdopendir(raw_fd) };
        match NonNull::new(dir) {
            Some(dir) => Ok(Self(dir)),
            None => {
                let error = io::Error::last_os_error();
                // SAFETY: `fdopendir` failed, so `raw_fd` remains caller-owned.
                drop(unsafe { OwnedFd::from_raw_fd(raw_fd) });
                Err(error)
            }
        }
    }

    pub fn open(dir_fd: BorrowedFd<'_>) -> io::Result<Self> {
        Self::from_owned(reopen_directory(dir_fd)?)
    }

    pub fn next_entry(&mut self) -> io::Result<Option<DirEntryName>> {
        fault_check!("directory_stream_next");
        loop {
            let Some(name) = self.next_raw()? else {
                return Ok(None);
            };
            if name.as_bytes() != b"." && name.as_bytes() != b".." {
                return Ok(Some(name));
            }
        }
    }

    fn next_raw(&mut self) -> io::Result<Option<DirEntryName>> {
        // SAFETY: the thread-local errno location is writable for this thread.
        unsafe { *libc::__errno_location() = 0 };
        // SAFETY: `self.0` is a live DIR stream owned by this value.
        let entry = unsafe { libc::readdir(self.0.as_ptr()) };
        if entry.is_null() {
            // SAFETY: the thread-local errno location remains valid.
            let errno = unsafe { *libc::__errno_location() };
            return if errno == 0 {
                Ok(None)
            } else {
                Err(io::Error::from_raw_os_error(errno))
            };
        }
        // SAFETY: `entry` is valid until the next directory-stream operation.
        // The name bytes are copied before returning.
        let name = unsafe {
            let name_ptr = (*entry).d_name.as_ptr();
            let len = libc::strlen(name_ptr);
            std::slice::from_raw_parts(name_ptr.cast::<u8>(), len)
        };
        Ok(Some(DirEntryName(name.to_vec())))
    }
}

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        // SAFETY: this value uniquely owns the live DIR stream.
        unsafe { libc::closedir(self.0.as_ptr()) };
    }
}

fn reopen_directory(dir_fd: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    open_directory(dir_fd, ".")
}

/// Read directory entries without losing non-UTF-8 names.
/// Consumes the owned descriptor and rejects directories exceeding either
/// bound before retaining an unbounded collection.
fn read_dir_entry_names_impl<F>(
    dir_fd: OwnedFd,
    max_entries: usize,
    max_name_bytes: usize,
    mut should_stop: F,
) -> Result<DirectoryEnumeration, DirectoryEnumerationProgressError>
where
    F: FnMut() -> io::Result<bool>,
{
    let mut entries = Vec::new();
    let mut name_bytes_read = 0usize;
    let mut progress = DirectoryEnumerationProgress::default();
    let mut dir = DirectoryStream::from_owned(dir_fd)
        .map_err(|error| DirectoryEnumerationProgressError::Io { error, progress })?;

    loop {
        match should_stop() {
            Ok(true) => {
                return Err(DirectoryEnumerationProgressError::Cancelled(progress));
            }
            Ok(false) => {}
            Err(error) => {
                return Err(DirectoryEnumerationProgressError::CancellationCheck {
                    error,
                    progress,
                });
            }
        }
        let Some(name) = dir
            .next_raw()
            .map_err(|error| DirectoryEnumerationProgressError::Io { error, progress })?
        else {
            break;
        };
        let name_bytes = name.as_bytes();
        if name_bytes != b"." && name_bytes != b".." {
            progress.entries_read = progress.entries_read.saturating_add(1);
            progress.name_bytes_read = progress.name_bytes_read.saturating_add(name_bytes.len());
            let Some(next_name_bytes) = name_bytes_read.checked_add(name_bytes.len()) else {
                return Err(DirectoryEnumerationProgressError::Io {
                    error: io::Error::new(
                        io::ErrorKind::FileTooLarge,
                        "directory entry byte count overflow",
                    ),
                    progress,
                });
            };
            if entries.len() >= max_entries || next_name_bytes > max_name_bytes {
                return Err(DirectoryEnumerationProgressError::Io {
                    error: io::Error::new(
                        io::ErrorKind::FileTooLarge,
                        "directory exceeds configured recovery scan bound",
                    ),
                    progress,
                });
            }
            name_bytes_read = next_name_bytes;
            entries.push(name);
        }
    }

    fault::permute_directory_entries(&mut entries);

    Ok(DirectoryEnumeration { entries, progress })
}

fn read_dir_entries_impl(dir_fd: OwnedFd) -> io::Result<Vec<DirEntryName>> {
    read_dir_entry_names_impl(dir_fd, usize::MAX, usize::MAX, || Ok(false))
        .map_err(DirectoryEnumerationProgressError::into_legacy)
        .map_err(DirectoryEnumerationError::into_io_error)
        .map(|enumeration| enumeration.entries)
}

/// Get the filesystem type magic number.
pub fn fs_type_magic(path: &Path) -> io::Result<i64> {
    let stat = statfs(path)?;
    Ok(stat.f_type as i64)
}

/// Known filesystem magic numbers.
pub const EXT4_SUPER_MAGIC: i64 = 0xEF53;
pub const XFS_SUPER_MAGIC: i64 = 0x58465342;
pub const BTRFS_SUPER_MAGIC: i64 = 0x9123683E;
pub const F2FS_SUPER_MAGIC: i64 = 0xF00D;
/// statfs(2) on f2fs as reported by kernel 6.8: the on-disk superblock
/// magic, not the uapi constant above. Accept both.
pub const F2FS_STATFS_MAGIC_ALT: i64 = 0xF2F5_2010;
pub const ZFS_SUPER_MAGIC: i64 = 0x2fc12fc1;
pub const TMPFS_MAGIC: i64 = 0x01021994;
pub const NFS_SUPER_MAGIC: i64 = 0x6969;
pub const OVERLAYFS_SUPER_MAGIC: i64 = 0x794c7630;
pub const FUSE_SUPER_MAGIC: i64 = 0x65735546;

/// Name of a queue-supported filesystem, if `magic` is one of them.
/// f2fs reports either `F2FS_SUPER_MAGIC` or `F2FS_STATFS_MAGIC_ALT`.
pub fn supported_filesystem_name(magic: i64) -> Option<&'static str> {
    match magic {
        EXT4_SUPER_MAGIC => Some("ext4"),
        XFS_SUPER_MAGIC => Some("xfs"),
        BTRFS_SUPER_MAGIC => Some("btrfs"),
        F2FS_SUPER_MAGIC | F2FS_STATFS_MAGIC_ALT => Some("f2fs"),
        ZFS_SUPER_MAGIC => Some("zfs"),
        _ => None,
    }
}

/// Read directory entries without consuming the descriptor or its position.
pub fn read_dir_entries(dir_fd: BorrowedFd<'_>) -> io::Result<Vec<DirEntryName>> {
    read_dir_entries_impl(reopen_directory(dir_fd)?)
}

/// Read byte-preserving directory entries without consuming the caller's fd.
/// The function returns an error rather than materializing more than the
/// configured entry or aggregate-name-byte bound.
pub fn read_dir_entries_bounded(
    dir_fd: BorrowedFd<'_>,
    max_entries: usize,
    max_name_bytes: usize,
) -> io::Result<Vec<DirEntryName>> {
    read_dir_entries_bounded_until(dir_fd, max_entries, max_name_bytes, || Ok(false))
        .map_err(DirectoryEnumerationError::into_io_error)
}

/// Read bounded byte-preserving directory entries with cooperative cancellation.
pub fn read_dir_entries_bounded_until<F>(
    dir_fd: BorrowedFd<'_>,
    max_entries: usize,
    max_name_bytes: usize,
    should_stop: F,
) -> Result<Vec<DirEntryName>, DirectoryEnumerationError>
where
    F: FnMut() -> io::Result<bool>,
{
    read_dir_entries_bounded_until_with_progress(dir_fd, max_entries, max_name_bytes, should_stop)
        .map(|enumeration| enumeration.entries)
        .map_err(DirectoryEnumerationProgressError::into_legacy)
}

/// Read bounded byte-preserving entries and retain exact partial progress.
pub fn read_dir_entries_bounded_until_with_progress<F>(
    dir_fd: BorrowedFd<'_>,
    max_entries: usize,
    max_name_bytes: usize,
    should_stop: F,
) -> Result<DirectoryEnumeration, DirectoryEnumerationProgressError>
where
    F: FnMut() -> io::Result<bool>,
{
    let reopened =
        reopen_directory(dir_fd).map_err(|error| DirectoryEnumerationProgressError::Io {
            error,
            progress: DirectoryEnumerationProgress::default(),
        })?;
    read_dir_entry_names_impl(reopened, max_entries, max_name_bytes, should_stop)
}

/// Change file mode relative to a directory fd.
pub fn fchmodat(dir_fd: BorrowedFd<'_>, name: &str, mode: u32) -> io::Result<()> {
    let c_name = cstr_from_name(name)?;
    // SAFETY: `c_name` is NUL-terminated and `dir_fd` remains live for the call.
    let rc = unsafe { libc::fchmodat(dir_fd.as_raw_fd(), c_name.as_ptr(), mode, 0) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Change file mode on an open fd.
pub fn fchmod(fd: BorrowedFd<'_>, mode: u32) -> io::Result<()> {
    // SAFETY: `fd` remains live for the synchronous syscall.
    let rc = unsafe { libc::fchmod(fd.as_raw_fd(), mode) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Stabilization sync: sync a verified destination and its parent directories.
/// Non-mutating: only performs fsync, no rename or write.
pub fn stabilize(fd: BorrowedFd<'_>) -> io::Result<()> {
    fsync(fd)
}

/// Stabilize a directory by its fd.
pub fn stabilize_dir(fd: BorrowedFd<'_>) -> io::Result<()> {
    fsync_dir_fd(fd)
}

/// Check if an error indicates the source is gone (ENOENT).
pub fn is_source_gone(err: &io::Error) -> bool {
    err.raw_os_error() == Some(libc::ENOENT)
}

/// Check if an error indicates a collision (EEXIST).
pub fn is_collision(err: &io::Error) -> bool {
    err.raw_os_error() == Some(libc::EEXIST)
}

/// Probe unnamed-file publication modes. Returns which mode is available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationMode {
    DirectAtEmptyPath,
    ProcSelfFd,
    NamedFallback,
}

/// Probe publication capability by creating a temp file and trying to link it.
pub fn probe_publication_mode(dir_fd: BorrowedFd<'_>) -> io::Result<PublicationMode> {
    let tmp = match open_tmpfile(dir_fd) {
        Ok(fd) => fd,
        Err(_) => return Ok(PublicationMode::NamedFallback),
    };

    // Write a byte so it's not empty
    write_all(tmp.as_fd(), b"x")?;

    let rand = random_128bit()?;
    let probe_name = format!(
        ".pubprobe-{}\0",
        rand.iter().map(|x| format!("{x:02x}")).collect::<String>()
    );

    // Try AT_EMPTY_PATH first
    let name = probe_name.trim_end_matches('\0');
    if linkat_empty_path(tmp.as_fd(), dir_fd, name).is_ok() {
        let _ = unlinkat(dir_fd, name);
        return Ok(PublicationMode::DirectAtEmptyPath);
    }

    if linkat_proc_self_fd(tmp.as_fd(), dir_fd, name).is_ok() {
        let _ = unlinkat(dir_fd, name);
        return Ok(PublicationMode::ProcSelfFd);
    }

    Ok(PublicationMode::NamedFallback)
}

/// Probe no-overwrite rename support.
pub fn probe_rename_noreplace(dir_fd: BorrowedFd<'_>) -> io::Result<bool> {
    let rand1 = random_128bit()?;
    let rand2 = random_128bit()?;
    let name1 = format!(
        ".rnprobe1-{}\0",
        rand1.iter().map(|x| format!("{x:02x}")).collect::<String>()
    );
    let name2 = format!(
        ".rnprobe2-{}\0",
        rand2.iter().map(|x| format!("{x:02x}")).collect::<String>()
    );
    let n1 = name1.trim_end_matches('\0');
    let n2 = name2.trim_end_matches('\0');

    let f1 = create_exclusive(dir_fd, n1, 0o600)?;
    let f2 = create_exclusive(dir_fd, n2, 0o600)?;
    drop(f1);
    drop(f2);

    // Only EEXIST proves RENAME_NOREPLACE support; unsupported kernels fail differently.
    let result = renameat2_noreplace(dir_fd, n1, dir_fd, n2);
    let works = result.is_err_and(|e| e.raw_os_error() == Some(libc::EEXIST));

    let _ = unlinkat(dir_fd, n1);
    let _ = unlinkat(dir_fd, n2);

    Ok(works)
}

/// Probe directory fsync support.
pub fn probe_dir_fsync(dir_fd: BorrowedFd<'_>) -> io::Result<bool> {
    match fsync_dir_fd(dir_fd) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Check if a path is absolute (starts with '/').
pub fn is_absolute_path(s: &str) -> bool {
    s.starts_with('/')
}

/// Validate a relative path component for safety:
/// rejects slashes, dot components, empty components, NUL, and noncanonical bytes.
pub fn validate_path_component(comp: &str) -> io::Result<()> {
    if comp.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty path component",
        ));
    }
    if comp == ".." || comp == "." {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path component is '.' or '..'",
        ));
    }
    if comp.contains('/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "slash in path component",
        ));
    }
    if comp.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NUL byte in path component",
        ));
    }
    if !comp.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path component contains noncanonical ASCII",
        ));
    }
    if comp.len() > MAX_COMPONENT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path component exceeds 255 bytes",
        ));
    }
    Ok(())
}

/// Validate a relative path for safety: rejects absolute paths, '.' and '..'.
pub fn validate_relative_path(path: &str) -> io::Result<ValidatedRelativePath<'_>> {
    if path.starts_with('/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "absolute path not allowed",
        ));
    }
    if path.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty path"));
    }
    if path.len() > MAX_RELATIVE_PATH_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "relative path exceeds 4095 bytes",
        ));
    }
    for comp in path.split('/') {
        if comp.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty path component in relative path",
            ));
        }
        validate_path_component(comp)?;
    }
    Ok(ValidatedRelativePath { path })
}

#[cfg(test)]
mod tests {
    #[test]
    fn reset_restores_the_pinned_realtime_clock() {
        fault::reset();
        assert!(fault::clock_realtime_ns().is_none());
        fault::pin_clock_realtime_ns(7);
        fault::set_clock_realtime_ns(9);
        assert_eq!(fault::clock_realtime_ns(), Some(9));
        fault::reset();
        assert_eq!(fault::clock_realtime_ns(), Some(7));
        assert_eq!(super::clock_realtime_ns().unwrap(), 7);
    }

    use super::*;
    use std::os::fd::{AsFd, RawFd};

    fn assert_fd_released(fd: RawFd, expected_device: u64, expected_inode: u64) {
        // SAFETY: Linux `stat` contains only integer fields and may be zero-initialized.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `stat` is writable for the duration of the syscall. The raw
        // descriptor is inspected only to prove the transferred handle was released.
        if unsafe { libc::fstat(fd, &mut stat) } == 0 {
            assert_ne!(
                (stat.st_dev, stat.st_ino),
                (expected_device, expected_inode)
            );
        } else {
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
        }
    }

    fn test_dir(label: &str) -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix(&format!("steadq_{label}_"))
            .tempdir()
            .unwrap()
    }

    #[test]
    fn test_directories_are_exclusive_and_owned() {
        let first = test_dir("isolation");
        let first_path = first.path().to_path_buf();
        let second = test_dir("isolation");
        let second_path = second.path().to_path_buf();

        assert_ne!(first_path, second_path);
        assert!(first_path.is_dir());
        assert!(second_path.is_dir());
        drop(first);
        assert!(!first_path.exists());
        assert!(second_path.is_dir());
    }

    #[test]
    fn boot_id_available() {
        let boot_id = read_boot_id().unwrap();
        assert_eq!(boot_id.len(), 36);
    }

    #[test]
    fn clock_boottime_positive() {
        let now = clock_boottime_ns().unwrap();
        assert!(now > 0);
    }

    #[test]
    fn timespec_to_unix_ns_rejects_pre_epoch() {
        let ts = |sec, nsec| libc::timespec {
            tv_sec: sec,
            tv_nsec: nsec,
        };
        assert!(timespec_to_unix_ns(&ts(-1, 0)).is_err());
        assert!(timespec_to_unix_ns(&ts(0, -1)).is_err());
        assert_eq!(timespec_to_unix_ns(&ts(0, 0)).unwrap(), 0);
        assert_eq!(timespec_to_unix_ns(&ts(2, 5)).unwrap(), 2_000_000_005);
    }

    #[test]
    fn is_eagain_classifies_errno() {
        assert!(is_eagain(&io::Error::from_raw_os_error(libc::EAGAIN)));
        assert!(!is_eagain(&io::Error::from_raw_os_error(libc::EIO)));
        assert!(!is_eagain(&io::Error::new(io::ErrorKind::Interrupted, "x")));
    }

    #[test]
    fn is_interrupted_classifies_kind() {
        assert!(is_interrupted(&io::Error::new(
            io::ErrorKind::Interrupted,
            "x"
        )));
        assert!(is_interrupted(&io::Error::from_raw_os_error(libc::EINTR)));
        assert!(!is_interrupted(&io::Error::from_raw_os_error(libc::EIO)));
    }

    #[test]
    fn probe_rename_noreplace_classifies_by_errno() {
        let dir = test_dir("rnprobe");
        let fd = open_dir_absolute(dir.path()).unwrap();

        // EEXIST from the no-replace rename proves support.
        fault::inject_errno("renameat2_noreplace", 1, libc::EEXIST);
        assert!(probe_rename_noreplace(fd.as_fd()).unwrap());
        fault::reset();

        // Any other errno means the kernel lacks RENAME_NOREPLACE.
        fault::inject_errno("renameat2_noreplace", 1, libc::ENOSYS);
        assert!(!probe_rename_noreplace(fd.as_fd()).unwrap());
        fault::reset();
    }

    #[test]
    fn clock_realtime_positive() {
        let now = clock_realtime_ns().unwrap();
        assert!(now > 0);
    }

    #[test]
    fn clock_monotonic_positive() {
        let now = clock_monotonic_ns().unwrap();
        assert!(now > 0);
    }

    #[test]
    fn random_128_bit_is_random() {
        let a = random_128bit().unwrap();
        let b = random_128bit().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn fsync_dir_fd_always_syncs() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("ready/0000")).unwrap();
        let root = std::fs::File::open(tmp.path()).unwrap();
        let ready_fd = open_directory(root.as_fd(), "ready").unwrap();
        let fd = open_directory(ready_fd.as_fd(), "0000").unwrap();
        assert!(fsync_dir_fd(fd.as_fd()).is_ok());
        assert!(fsync_dir_fd(fd.as_fd()).is_ok());
    }

    #[test]
    fn writev_writes_all_buffers_in_order() {
        let tmp = tempfile::tempdir().unwrap();
        let fd = create_exclusive(
            std::fs::File::open(tmp.path()).unwrap().as_fd(),
            "writev_test",
            0o600,
        )
        .unwrap();
        let part1 = b"hello ";
        let part2 = b"world ";
        let part3 = b"writev!";
        writev_all(fd.as_fd(), &[part1, part2, part3]).unwrap();
        drop(fd);

        let data = std::fs::read(tmp.path().join("writev_test")).unwrap();
        assert_eq!(data, b"hello world writev!");
    }

    #[test]
    fn writev_handles_empty_buffers() {
        let tmp = tempfile::tempdir().unwrap();
        let fd = create_exclusive(
            std::fs::File::open(tmp.path()).unwrap().as_fd(),
            "writev_empty",
            0o600,
        )
        .unwrap();
        writev_all(fd.as_fd(), &[b"", b"data", b""]).unwrap();
        drop(fd);

        let data = std::fs::read(tmp.path().join("writev_empty")).unwrap();
        assert_eq!(data, b"data");
    }

    #[test]
    fn write_all_persists_every_byte() {
        let directory = test_dir("write_all");
        let dir: OwnedFd = std::fs::File::open(directory.path()).unwrap().into();
        let file = create_exclusive(dir.as_fd(), "data", 0o600).unwrap();
        write_all(file.as_fd(), b"complete").unwrap();
        let mut bytes = [0u8; 8];
        pread_exact(file.as_fd(), &mut bytes, 0).unwrap();
        assert_eq!(&bytes, b"complete");
        drop(file);
        drop(dir);
    }

    #[test]
    fn ofd_write_lock_reports_acquired_and_contended() {
        let directory = test_dir("write_lock");
        let dir: OwnedFd = std::fs::File::open(directory.path()).unwrap().into();
        let first = create_exclusive(dir.as_fd(), "lock", 0o600).unwrap();
        let second = openat(dir.as_fd(), "lock", libc::O_RDWR, 0).unwrap();
        assert!(try_ofd_write_lock(first.as_fd()).unwrap());
        assert!(!try_ofd_write_lock(second.as_fd()).unwrap());
        drop(second);
        drop(first);
        drop(dir);
    }

    #[test]
    fn ofd_read_lock_reports_acquired_and_writer_contention() {
        let directory = test_dir("read_lock");
        let dir: OwnedFd = std::fs::File::open(directory.path()).unwrap().into();
        let reader = create_exclusive(dir.as_fd(), "lock", 0o600).unwrap();
        assert!(try_ofd_read_lock(reader.as_fd()).unwrap());
        drop(reader);

        let writer = openat(dir.as_fd(), "lock", libc::O_RDWR, 0).unwrap();
        let blocked_reader = openat(dir.as_fd(), "lock", libc::O_RDWR, 0).unwrap();
        assert!(try_ofd_write_lock(writer.as_fd()).unwrap());
        assert!(!try_ofd_read_lock(blocked_reader.as_fd()).unwrap());
        drop(blocked_reader);
        drop(writer);
        drop(dir);
    }

    #[test]
    fn random_is_not_all_zero() {
        for _ in 0..100 {
            let r = random_128bit().unwrap();
            assert_ne!(r, [0u8; 16], "random_128bit returned all zeros");
        }
    }

    #[test]
    fn get_random_fills_buffer() {
        let buf = get_random(256).unwrap();
        assert_eq!(buf.len(), 256);
        // Extremely unlikely that 256 random bytes are all zero
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn get_random_zero_returns_empty() {
        let buf = get_random(0).unwrap();
        assert!(buf.is_empty());
    }

    #[test]
    fn nul_in_name_returns_error() {
        let result = cstr_from_name("hello\0world");
        assert!(result.is_err());
    }

    #[test]
    fn syscall_paths_keep_canonical_names_inline_and_long_paths_valid() {
        let inline = cstr_from_name("ready-name.sqj").unwrap();
        assert!(matches!(inline, CPath::Inline(_)));
        // SAFETY: CPath guarantees a trailing NUL for the lifetime of `inline`.
        let inline_bytes = unsafe { std::ffi::CStr::from_ptr(inline.as_ptr()) }.to_bytes();
        assert_eq!(inline_bytes, b"ready-name.sqj");

        let boundary_name = "b".repeat(MAX_COMPONENT_BYTES);
        let boundary = cstr_from_name(&boundary_name).unwrap();
        assert!(matches!(boundary, CPath::Inline(_)));
        // SAFETY: CPath guarantees a trailing NUL for the lifetime of `boundary`.
        let boundary_bytes = unsafe { std::ffi::CStr::from_ptr(boundary.as_ptr()) }.to_bytes();
        assert_eq!(boundary_bytes, boundary_name.as_bytes());

        let long_name = "x".repeat(INLINE_C_PATH_BYTES);
        let heap = cstr_from_name(&long_name).unwrap();
        assert!(matches!(heap, CPath::Heap(_)));
        // SAFETY: CPath guarantees a trailing NUL for the lifetime of `heap`.
        let heap_bytes = unsafe { std::ffi::CStr::from_ptr(heap.as_ptr()) }.to_bytes();
        assert_eq!(heap_bytes, long_name.as_bytes());
    }

    #[test]
    fn proc_self_fd_path_encodes_the_live_descriptor_without_allocation() {
        let directory = test_dir("proc_self_fd_path");
        let fd: OwnedFd = std::fs::File::open(directory.path()).unwrap().into();
        let path = proc_self_fd_path(fd.as_fd());
        // SAFETY: proc_self_fd_path leaves zero-filled bytes after the digits.
        let actual = unsafe { std::ffi::CStr::from_ptr(path.as_ptr().cast()) };
        assert_eq!(
            actual.to_bytes(),
            format!("/proc/self/fd/{}", fd.as_raw_fd()).as_bytes()
        );

        let multiple_digits = proc_self_fd_path_raw(1234);
        // SAFETY: proc_self_fd_path_raw leaves zero-filled bytes after the digits.
        let actual = unsafe { std::ffi::CStr::from_ptr(multiple_digits.as_ptr().cast()) };
        assert_eq!(actual.to_bytes(), b"/proc/self/fd/1234");
    }

    #[test]
    fn supported_filesystem_name_covers_certified_backends() {
        assert_eq!(supported_filesystem_name(EXT4_SUPER_MAGIC), Some("ext4"));
        assert_eq!(supported_filesystem_name(XFS_SUPER_MAGIC), Some("xfs"));
        assert_eq!(supported_filesystem_name(BTRFS_SUPER_MAGIC), Some("btrfs"));
        assert_eq!(supported_filesystem_name(F2FS_SUPER_MAGIC), Some("f2fs"));
        assert_eq!(
            supported_filesystem_name(F2FS_STATFS_MAGIC_ALT),
            Some("f2fs")
        );
        assert_eq!(supported_filesystem_name(ZFS_SUPER_MAGIC), Some("zfs"));
        assert_eq!(supported_filesystem_name(TMPFS_MAGIC), None);
        assert_eq!(supported_filesystem_name(0xdead), None);
    }

    #[test]
    fn path_validation_rejects_dotdot() {
        assert!(validate_path_component("..").is_err());
        assert!(validate_path_component(".").is_err());
        assert!(validate_path_component("").is_err());
        assert!(validate_path_component("/abs").is_err());
        assert!(validate_path_component("a/b").is_err());
        assert!(validate_path_component("non-ascii-\u{00e9}").is_err());
        assert!(validate_path_component("with space").is_err());
        assert!(validate_path_component("with\ttab").is_err());
        assert!(validate_path_component("with\nnewline").is_err());
        assert!(validate_path_component(&"a".repeat(256)).is_err());
        assert!(validate_path_component(&"a".repeat(255)).is_ok());
        assert!(validate_path_component("ok").is_ok());
    }

    #[test]
    fn validate_relative_path_rejects_absolute_and_empty() {
        let path_with_len = |length: usize| {
            assert_eq!(length % 2, 1);
            "a/".repeat(length / 2) + "a"
        };
        assert!(validate_relative_path("/etc/passwd").is_err());
        assert!(validate_relative_path("").is_err());
        assert!(validate_relative_path("a//b").is_err());
        assert!(validate_relative_path("a/b/").is_err());
        assert!(validate_relative_path("a/./b").is_err());
        assert!(validate_relative_path("a/../b").is_err());
        assert!(validate_relative_path("a/b\0c").is_err());
        assert!(validate_relative_path(&path_with_len(4095)).is_ok());
        assert!(validate_relative_path(&path_with_len(4097)).is_err());
        assert_eq!(validate_relative_path("a/b").unwrap().as_str(), "a/b");
        assert_eq!(
            validate_relative_path("a/b/c")
                .unwrap()
                .components()
                .collect::<Vec<_>>(),
            vec!["a", "b", "c"]
        );
    }

    #[test]
    fn open_directory_beneath_opens_nested_directory() {
        let base = test_dir("openat2_nested");
        std::fs::create_dir_all(base.path().join("root/a/b")).unwrap();
        let root = std::fs::File::open(base.path().join("root")).unwrap();
        let path = ValidatedRelativePath::new("a/b").unwrap();
        let opened = open_directory_beneath(root.as_fd(), path).unwrap();
        let stat = fstat(opened.as_fd()).unwrap();
        assert_eq!(stat.st_mode & libc::S_IFMT, libc::S_IFDIR);
        // SAFETY: `opened` owns a valid descriptor for the duration of the call.
        let descriptor_flags = unsafe { libc::fcntl(opened.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(descriptor_flags, -1);
        assert_ne!(descriptor_flags & libc::FD_CLOEXEC, 0);
    }

    #[test]
    fn open_directory_beneath_rejects_symlink_escape() {
        use std::os::unix::fs::symlink;

        let base = test_dir("openat2_symlink");
        std::fs::create_dir_all(base.path().join("root")).unwrap();
        std::fs::create_dir_all(base.path().join("outside/secret")).unwrap();
        let root = std::fs::File::open(base.path().join("root")).unwrap();
        let path = ValidatedRelativePath::new("link/secret").unwrap();
        symlink(base.path().join("outside"), base.path().join("root/link")).unwrap();
        assert!(open_directory_beneath(root.as_fd(), path).is_err());
    }

    #[test]
    fn open_directory_beneath_enforces_kernel_beneath_and_directory_flags() {
        let base = test_dir("openat2_policy");
        std::fs::create_dir_all(base.path().join("root")).unwrap();
        std::fs::create_dir_all(base.path().join("outside")).unwrap();
        std::fs::write(base.path().join("root/file"), b"not a directory").unwrap();
        let root = std::fs::File::open(base.path().join("root")).unwrap();

        let forged_escape = ValidatedRelativePath { path: "../outside" };
        assert!(open_directory_beneath(root.as_fd(), forged_escape).is_err());

        let file = ValidatedRelativePath::new("file").unwrap();
        assert!(open_directory_beneath(root.as_fd(), file).is_err());

        assert_eq!(RESOLVER_RESOLVE_FLAGS, 0x0e);
        assert_eq!(resolver_open_flags(), libc::O_DIRECTORY | libc::O_CLOEXEC);
    }

    #[test]
    fn open_directory_beneath_does_not_fallback_on_enosys() {
        let base = test_dir("openat2_enosys");
        std::fs::create_dir_all(base.path().join("root/a")).unwrap();
        let root = std::fs::File::open(base.path().join("root")).unwrap();
        let path = ValidatedRelativePath::new("a").unwrap();

        fault::reset();
        fault::inject_errno("openat2_beneath", 1, libc::ENOSYS);
        let error = open_directory_beneath(root.as_fd(), path).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENOSYS));
        assert_eq!(fault::call_count("openat2_beneath"), 1);
        assert_eq!(fault::call_count("open_directory"), 0);
        fault::reset();
    }

    #[test]
    fn directory_stream_closes_consumed_descriptor_on_success_and_failure() {
        let directory_owner = test_dir("directory-stream-ownership");
        let dir_path = directory_owner.path();

        let directory: OwnedFd = std::fs::File::open(dir_path).unwrap().into();
        let directory_fd = directory.as_raw_fd();
        let directory_stat = fstat(directory.as_fd()).unwrap();
        let stream = DirectoryStream::from_owned(directory).unwrap();
        drop(stream);
        assert_fd_released(directory_fd, directory_stat.st_dev, directory_stat.st_ino);

        let file_path = dir_path.join("plain-file");
        std::fs::write(&file_path, b"data").unwrap();
        let file: OwnedFd = std::fs::File::open(file_path).unwrap().into();
        let file_fd = file.as_raw_fd();
        let file_stat = fstat(file.as_fd()).unwrap();
        let error = match DirectoryStream::from_owned(file) {
            Ok(_) => panic!("fdopendir accepted a regular file"),
            Err(error) => error,
        };
        assert_eq!(error.raw_os_error(), Some(libc::ENOTDIR));
        assert_fd_released(file_fd, file_stat.st_dev, file_stat.st_ino);
    }

    #[test]
    fn borrowed_enumeration_failure_keeps_caller_descriptor_open() {
        let directory = test_dir("borrowed-enumeration-failure");
        let path = directory.path().join("plain-file");
        std::fs::write(&path, b"data").unwrap();
        let file = std::fs::File::open(&path).unwrap();

        let error = read_dir_entries(file.as_fd()).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENOTDIR));
        assert_eq!(fstat(file.as_fd()).unwrap().st_size, 4);
    }

    #[test]
    fn bounded_directory_read_preserves_distinct_non_utf8_names() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let directory = test_dir("raw-directory-names");
        let dir_path = directory.path();
        std::fs::write(dir_path.join("plain"), b"plain").unwrap();
        // Skip on filesystems with mandatory UTF-8 names (ZFS utf8only,
        // ext4 strict encoding); they reject the inputs with EILSEQ.
        match std::fs::write(
            dir_path.join(std::ffi::OsStr::from_bytes(b"probe-\x80")),
            b"",
        ) {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(libc::EILSEQ) => return,
            Err(e) => panic!("probe write failed: {e}"),
        }
        std::fs::remove_file(dir_path.join(std::ffi::OsStr::from_bytes(b"probe-\x80"))).unwrap();
        let first = OsStr::from_bytes(b"bad-\x80");
        let second = OsStr::from_bytes(b"bad-\x81");
        std::fs::write(dir_path.join(first), b"a").unwrap();
        std::fs::write(dir_path.join(second), b"b").unwrap();
        let dir = std::fs::File::open(dir_path).unwrap();

        let mut entries = read_dir_entries_bounded(dir.as_fd(), 3, 510).unwrap();
        entries.sort();
        assert_eq!(entries[0].as_bytes(), b"bad-\x80");
        assert_eq!(entries[1].as_bytes(), b"bad-\x81");
        assert_eq!(entries[2].as_bytes(), b"plain");
        assert_eq!(entries[0].as_str(), None);
        assert_eq!(entries[1].as_str(), None);
        assert_eq!(entries[2].as_str(), Some("plain"));
        assert_eq!(entries[2].as_ascii_str(), Some("plain"));
        assert_eq!(format!("{:?}", entries[0]), "b\"bad-\\x80\"");

        let mut owned = read_dir_entries(dir.as_fd()).unwrap();
        owned.sort();
        assert_eq!(owned[0].as_bytes(), b"bad-\x80");
        assert_eq!(owned[1].as_bytes(), b"bad-\x81");
    }

    #[test]
    fn protocol_text_rejects_non_ascii_utf8() {
        let name = DirEntryName("café".as_bytes().to_vec());
        assert_eq!(name.as_str(), Some("café"));
        assert_eq!(name.as_ascii_str(), None);
    }

    #[test]
    fn bounded_directory_read_applies_thread_local_permutation() {
        let directory = test_dir("permuted-directory-read");
        let dir_path = directory.path();
        for name in ["a", "b", "c", "d"] {
            std::fs::write(dir_path.join(name), name.as_bytes()).unwrap();
        }
        let dir = std::fs::File::open(dir_path).unwrap();
        fault::reset();
        let baseline = read_dir_entries_bounded(dir.as_fd(), 4, usize::MAX).unwrap();

        for (rotation, reversed) in [(1, false), (3, false), (0, true), (2, true)] {
            let mut expected = baseline.clone();
            let rotation = rotation % expected.len();
            expected.rotate_left(rotation);
            if reversed {
                expected.reverse();
            }
            fault::permute_readdir(rotation, reversed);
            let actual = read_dir_entries_bounded(dir.as_fd(), 4, usize::MAX).unwrap();
            assert_eq!(actual, expected, "rotation={rotation} reversed={reversed}");
        }

        fault::reset();
        assert_eq!(
            read_dir_entries_bounded(dir.as_fd(), 4, usize::MAX).unwrap(),
            baseline
        );
    }

    #[test]
    fn bounded_directory_read_rejects_entry_and_byte_overflow() {
        let directory = test_dir("bounded-directory-read");
        let dir_path = directory.path();
        std::fs::write(dir_path.join("a"), b"a").unwrap();
        std::fs::write(dir_path.join("bb"), b"b").unwrap();
        let dir = std::fs::File::open(dir_path).unwrap();

        let entry_error = read_dir_entries_bounded(dir.as_fd(), 1, usize::MAX).unwrap_err();
        assert_eq!(entry_error.kind(), io::ErrorKind::FileTooLarge);
        let byte_error = read_dir_entries_bounded(dir.as_fd(), 2, 2).unwrap_err();
        assert_eq!(byte_error.kind(), io::ErrorKind::FileTooLarge);
        let mut exact_entries = read_dir_entries_bounded(dir.as_fd(), 2, 3).unwrap();
        exact_entries.sort();
        assert_eq!(exact_entries[0].as_bytes(), b"a");
        assert_eq!(exact_entries[1].as_bytes(), b"bb");
    }

    #[test]
    fn owned_directory_read_returns_exact_name_bytes() {
        let directory = test_dir("owned-directory-read");
        let dir_path = directory.path();
        std::fs::write(dir_path.join("alpha"), b"a").unwrap();
        std::fs::write(dir_path.join("beta"), b"b").unwrap();
        let dir = std::fs::File::open(dir_path).unwrap();

        let mut first = read_dir_entries(dir.as_fd()).unwrap();
        let mut second = read_dir_entries(dir.as_fd()).unwrap();
        first.sort();
        second.sort();
        assert_eq!(first, second);
        assert_eq!(first[0].as_bytes(), b"alpha");
        assert_eq!(first[1].as_bytes(), b"beta");
    }

    #[test]
    fn bounded_directory_read_stops_at_cooperative_deadline() {
        let directory = test_dir("bounded-directory-deadline");
        let dir_path = directory.path();
        std::fs::write(dir_path.join("alpha"), b"a").unwrap();
        let dir = std::fs::File::open(dir_path).unwrap();
        let mut checks = 0;

        let error = read_dir_entries_bounded_until_with_progress(
            dir.as_fd(),
            usize::MAX,
            usize::MAX,
            || {
                checks += 1;
                Ok(checks == 1)
            },
        )
        .unwrap_err();

        assert!(matches!(
            error,
            DirectoryEnumerationProgressError::Cancelled(DirectoryEnumerationProgress {
                entries_read: 0,
                name_bytes_read: 0,
            })
        ));
        assert_eq!(checks, 1);
        assert_eq!(read_dir_entries(dir.as_fd()).unwrap().len(), 1);
    }

    #[test]
    fn cancellable_directory_api_preserves_error_shape() {
        let directory = test_dir("bounded-directory-legacy-result");
        let dir_path = directory.path();
        std::fs::write(dir_path.join("alpha"), b"a").unwrap();
        let dir = std::fs::File::open(dir_path).unwrap();

        let entries =
            read_dir_entries_bounded_until(dir.as_fd(), usize::MAX, usize::MAX, || Ok(false))
                .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].as_bytes(), b"alpha");

        let error =
            read_dir_entries_bounded_until(dir.as_fd(), usize::MAX, usize::MAX, || Ok(true))
                .unwrap_err();
        assert!(matches!(error, DirectoryEnumerationError::Cancelled));
    }

    #[test]
    fn cancelled_directory_read_reports_partial_progress() {
        let directory = test_dir("bounded-directory-partial-progress");
        let dir_path = directory.path();
        for index in 0..32 {
            std::fs::write(dir_path.join(format!("entry-{index:02}")), b"x").unwrap();
        }
        let dir = std::fs::File::open(dir_path).unwrap();
        let mut checks = 0;

        let error = read_dir_entries_bounded_until_with_progress(
            dir.as_fd(),
            usize::MAX,
            usize::MAX,
            || {
                checks += 1;
                Ok(checks == 10)
            },
        )
        .unwrap_err();

        let progress = error.progress();
        assert!(matches!(
            error,
            DirectoryEnumerationProgressError::Cancelled(_)
        ));
        assert!(progress.entries_read > 0);
        assert!(progress.entries_read < 10);
        assert_eq!(progress.name_bytes_read, progress.entries_read * 8);
    }

    #[test]
    fn bounded_directory_read_distinguishes_cancellation_check_failure() {
        let directory = test_dir("bounded-directory-check-failure");
        let dir_path = directory.path();
        let dir = std::fs::File::open(dir_path).unwrap();

        let error = read_dir_entries_bounded_until_with_progress(
            dir.as_fd(),
            usize::MAX,
            usize::MAX,
            || Err(io::Error::from_raw_os_error(libc::ETIMEDOUT)),
        )
        .unwrap_err();

        assert!(matches!(
            error,
            DirectoryEnumerationProgressError::CancellationCheck {
                ref error,
                progress: DirectoryEnumerationProgress {
                    entries_read: 0,
                    name_bytes_read: 0,
                },
            } if error.raw_os_error() == Some(libc::ETIMEDOUT)
        ));
    }

    #[test]
    fn directory_enumeration_error_preserves_category_and_source() {
        use std::error::Error as _;

        let cancelled = DirectoryEnumerationError::Cancelled;
        assert_eq!(cancelled.to_string(), "directory enumeration cancelled");
        assert!(cancelled.source().is_none());

        let check = DirectoryEnumerationError::CancellationCheck(io::Error::from_raw_os_error(
            libc::ETIMEDOUT,
        ));
        assert!(check
            .to_string()
            .starts_with("directory cancellation check failed:"));
        assert_eq!(
            check
                .source()
                .and_then(|source| source.downcast_ref::<io::Error>())
                .and_then(io::Error::raw_os_error),
            Some(libc::ETIMEDOUT)
        );

        let io_error = DirectoryEnumerationError::Io(io::Error::from_raw_os_error(libc::EIO));
        assert_eq!(
            io_error
                .source()
                .and_then(|source| source.downcast_ref::<io::Error>())
                .and_then(io::Error::raw_os_error),
            Some(libc::EIO)
        );

        let progress = DirectoryEnumerationProgress {
            entries_read: 2,
            name_bytes_read: 7,
        };
        let progress_error = DirectoryEnumerationProgressError::Io {
            error: io::Error::from_raw_os_error(libc::EIO),
            progress,
        };
        assert_eq!(
            progress_error.to_string(),
            io::Error::from_raw_os_error(libc::EIO).to_string()
        );
        assert_eq!(
            progress_error
                .source()
                .and_then(|source| source.downcast_ref::<io::Error>())
                .and_then(io::Error::raw_os_error),
            Some(libc::EIO)
        );
        assert_eq!(progress_error.progress(), progress);
    }

    #[test]
    fn bounded_directory_read_reports_the_overflow_sentinel() {
        let directory = test_dir("bounded-directory-progress");
        let dir_path = directory.path();
        std::fs::write(dir_path.join("a"), b"a").unwrap();
        std::fs::write(dir_path.join("bb"), b"b").unwrap();
        let dir = std::fs::File::open(dir_path).unwrap();

        let error =
            read_dir_entries_bounded_until_with_progress(dir.as_fd(), 1, usize::MAX, || Ok(false))
                .unwrap_err();

        assert!(matches!(
            error,
            DirectoryEnumerationProgressError::Io {
                ref error,
                progress: DirectoryEnumerationProgress {
                    entries_read: 2,
                    name_bytes_read: 3,
                },
            } if error.kind() == io::ErrorKind::FileTooLarge
        ));
    }

    #[test]
    fn fault_inject_fsync_fires_once() {
        fault::reset();
        fault::inject("fsync", 1);
        // Use a real fd (stdout). The fault fires before the syscall.
        let stdout = std::io::stdout();
        let err = fsync(stdout.as_fd()).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EIO));
        // Second call is not faulted.
        let _ = fsync(stdout.as_fd());
        fault::reset();
    }

    #[test]
    fn borrowed_file_operations_preserve_the_owner() {
        fault::reset();
        let directory = test_dir("borrowed-file-owner");
        let dir = open_dir_absolute(directory.path()).unwrap();
        let file = create_exclusive(dir.as_fd(), "data", 0o600).unwrap();
        fchmod(file.as_fd(), 0o700).unwrap();
        assert_eq!(fstat(file.as_fd()).unwrap().st_mode & 0o777, 0o700);
        write_all(file.as_fd(), b"data").unwrap();
        // SAFETY: `file` owns this descriptor for the duration of the call.
        let offset = unsafe { libc::lseek(file.as_raw_fd(), 0, libc::SEEK_SET) };
        assert_eq!(offset, 0);
        let mut sequential = [0u8; 4];
        assert_eq!(read(file.as_fd(), &mut sequential).unwrap(), 4);
        assert_eq!(&sequential, b"data");

        fault::inject_errno("pread", 1, libc::EIO);
        let mut bytes = [0u8; 4];
        assert_eq!(
            pread_exact(file.as_fd(), &mut bytes, 0)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EIO)
        );
        // SAFETY: `file` owns this descriptor for the duration of the call.
        assert_ne!(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) }, -1);
        pread_exact(file.as_fd(), &mut bytes, 0).unwrap();
        assert_eq!(&bytes, b"data");

        fault::reset();
        drop(file);
        drop(dir);
    }

    #[test]
    fn borrowed_directory_operations_preserve_the_owner() {
        fault::reset();
        let directory_owner = test_dir("borrowed-directory-owner");
        let directory = open_dir_absolute(directory_owner.path()).unwrap();

        mkdirat(directory.as_fd(), "child", 0o700).unwrap();
        let child = open_directory(directory.as_fd(), "child").unwrap();
        create_exclusive(child.as_fd(), "source", 0o600).unwrap();
        fchmodat(child.as_fd(), "source", 0o400).unwrap();
        assert_eq!(
            fstatat(child.as_fd(), "source").unwrap().st_mode & 0o777,
            0o400
        );
        renameat2_noreplace(child.as_fd(), "source", child.as_fd(), "destination").unwrap();
        fsync_dir_fd(child.as_fd()).unwrap();
        unlinkat(child.as_fd(), "destination").unwrap();

        fault::inject_errno("open_directory", 1, libc::EIO);
        assert_eq!(
            open_directory(directory.as_fd(), "child")
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EIO)
        );
        assert_eq!(
            fstat(directory.as_fd()).unwrap().st_mode & libc::S_IFMT,
            libc::S_IFDIR
        );
        assert_eq!(
            fstat(child.as_fd()).unwrap().st_mode & libc::S_IFMT,
            libc::S_IFDIR
        );

        fault::reset();
        drop(child);
        drop(directory);
    }

    #[test]
    fn empty_write_is_a_noop_without_consuming_a_fault() {
        fault::reset();
        let directory = test_dir("empty-write");
        let dir = open_dir_absolute(directory.path()).unwrap();
        let file = create_exclusive(dir.as_fd(), "data", 0o600).unwrap();
        fault::inject_errno("write_all", 1, libc::EIO);

        write_all(file.as_fd(), b"").unwrap();
        assert_eq!(
            write_all(file.as_fd(), b"data").unwrap_err().raw_os_error(),
            Some(libc::EIO)
        );

        fault::reset();
        drop(file);
        drop(dir);
    }

    #[test]
    fn fault_inject_nth_call() {
        fault::reset();
        fault::inject("renameat2_noreplace", 2);
        let dir = test_dir("nth");
        let fd = open_dir_absolute(dir.path()).unwrap();
        std::fs::write(dir.path().join("src1"), b"1").unwrap();
        std::fs::write(dir.path().join("src2"), b"2").unwrap();
        let r1 = renameat2_noreplace(fd.as_fd(), "src1", fd.as_fd(), "dst1");
        assert!(r1.is_ok(), "first call should succeed: {r1:?}");
        let r2 = renameat2_noreplace(fd.as_fd(), "src2", fd.as_fd(), "dst2");
        assert!(r2.is_err(), "second call should fault: {r2:?}");
        assert_eq!(r2.unwrap_err().raw_os_error(), Some(libc::EIO));
        fault::reset();
    }

    #[test]
    fn fault_inject_errno_enotdir() {
        fault::reset();
        fault::inject_errno("fstatat", 1, libc::ENOTDIR);
        let dir = test_dir("enotdir");
        let fd = open_dir_absolute(dir.path()).unwrap();
        std::fs::write(dir.path().join("f"), b"x").unwrap();
        let err = fstatat(fd.as_fd(), "f").unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENOTDIR));
        fault::reset();
    }

    #[test]
    fn boottime_override_is_thread_local_and_resettable() {
        fault::reset();
        fault::set_clock_boottime_ns(1);
        assert_eq!(clock_boottime_ns().unwrap(), 1);
        assert!(
            std::thread::spawn(|| clock_boottime_ns().unwrap())
                .join()
                .unwrap()
                > 1
        );
        fault::reset();
        assert!(clock_boottime_ns().unwrap() > 1);
    }

    #[test]
    fn realtime_override_is_thread_local_and_resettable() {
        fault::reset();
        fault::set_clock_realtime_ns(1);
        assert_eq!(clock_realtime_ns().unwrap(), 1);
        assert!(
            std::thread::spawn(|| clock_realtime_ns().unwrap())
                .join()
                .unwrap()
                > 1
        );

        fault::reset();
        assert!(clock_realtime_ns().unwrap() > 1);
    }

    #[test]
    fn realtime_fault_precedes_fixed_value() {
        fault::reset();
        fault::set_clock_realtime_ns(1);
        fault::inject_errno("clock_realtime_ns", 1, libc::EIO);
        assert_eq!(
            clock_realtime_ns().unwrap_err().raw_os_error(),
            Some(libc::EIO)
        );
        assert_eq!(clock_realtime_ns().unwrap(), 1);
        fault::reset();
    }

    #[test]
    fn fault_idle_has_no_effect() {
        fault::reset();
        assert_eq!(fault::call_count("fsync"), 0);
        let dir = test_dir("idle");
        let fd = open_dir_absolute(dir.path()).unwrap();
        fsync(fd.as_fd()).unwrap();
        // Idle threads do not count checks when no faults are armed.
        assert_eq!(fault::call_count("fsync"), 0);
    }

    #[test]
    fn mkdirat_and_unlinkat_dir_round_trip() {
        let dir = test_dir("mkdir");
        let fd = open_dir_absolute(dir.path()).unwrap();
        mkdirat(fd.as_fd(), "child", 0o700).unwrap();
        // Open (not the Ok(())) proves creation, so no-op mutants fail.
        let child = open_directory(fd.as_fd(), "child").unwrap();
        drop(child);
        unlinkat_dir(fd.as_fd(), "child").unwrap();
        assert!(open_directory(fd.as_fd(), "child").is_err());
    }

    #[test]
    fn unlinkat_removes_file() {
        let dir = test_dir("unlink");
        let fd = open_dir_absolute(dir.path()).unwrap();
        std::fs::write(dir.path().join("f"), b"x").unwrap();
        fstatat(fd.as_fd(), "f").unwrap();
        unlinkat(fd.as_fd(), "f").unwrap();
        assert!(fstatat(fd.as_fd(), "f").is_err());
    }

    #[test]
    fn renameat_moves_file() {
        let dir = test_dir("renameat");
        let fd = open_dir_absolute(dir.path()).unwrap();
        std::fs::write(dir.path().join("a"), b"z").unwrap();
        renameat(fd.as_fd(), "a", fd.as_fd(), "b").unwrap();
        assert!(fstatat(fd.as_fd(), "a").is_err());
        assert!(fstatat(fd.as_fd(), "b").is_ok());
    }

    #[test]
    fn fsync_dir_and_fd_succeed() {
        let dir = test_dir("fsyncdir");
        let fd = open_dir_absolute(dir.path()).unwrap();
        std::fs::write(dir.path().join("x"), b"1").unwrap();
        fsync_dir_fd(fd.as_fd()).unwrap();
        // Nested child dir
        mkdirat(fd.as_fd(), "nested", 0o700).unwrap();
        fsync_dir(fd.as_fd(), "nested").unwrap();
    }

    #[test]
    fn fsync_dir_fd_honors_fault_injection() {
        // Arm a fault so no-op mutants can't pass without the real body.
        fault::reset();
        let dir = test_dir("fsyncdir-fault");
        let fd = open_dir_absolute(dir.path()).unwrap();
        fault::inject("fsync_dir_fd", 1);
        let err = fsync_dir_fd(fd.as_fd()).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EIO));
        fault::reset();
        fault::inject("fsync", 1);
        let err = fsync_dir_fd(fd.as_fd()).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EIO));
        fault::reset();
        fault::inject("fsync_dir", 1);
        mkdirat(fd.as_fd(), "nested", 0o700).unwrap();
        let err = fsync_dir(fd.as_fd(), "nested").unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EIO));
        fault::reset();
    }

    #[test]
    fn fsync_dir_fd_records_ordered_directory_identities() {
        fault::reset();
        let first_dir = test_dir("fsyncdir-record-first");
        let second_dir = test_dir("fsyncdir-record-second");
        let first_fd = open_dir_absolute(first_dir.path()).unwrap();
        let second_fd = open_dir_absolute(second_dir.path()).unwrap();
        let first_stat = fstat(first_fd.as_fd()).unwrap();
        let second_stat = fstat(second_fd.as_fd()).unwrap();
        let expected = [
            (first_stat.st_dev as u64, first_stat.st_ino as u64),
            (second_stat.st_dev as u64, second_stat.st_ino as u64),
        ];

        fault::inject("fsync_dir_fd", u64::MAX);
        fsync_dir_fd(first_fd.as_fd()).unwrap();
        fsync_dir_fd(second_fd.as_fd()).unwrap();
        assert_eq!(fault::fd_identities("fsync_dir_fd"), expected);
        assert_eq!(fault::call_count("fsync_dir_fd"), 2);

        let error = fault::record_fd_identity("invalid", -1).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EBADF));

        fault::reset();
        assert!(fault::fd_identities("fsync_dir_fd").is_empty());
    }

    #[test]
    fn clocks_return_plausible_values() {
        // Kill Ok(1) whole-function mutants: real clocks are far above 1.
        let boot = clock_boottime_ns().unwrap();
        let mono = clock_monotonic_ns().unwrap();
        let real = clock_realtime_ns().unwrap();
        assert!(boot > 1_000_000, "boottime too small: {boot}");
        assert!(mono > 1_000_000, "monotonic too small: {mono}");
        // Realtime after 2020-01-01 in nanoseconds.
        assert!(
            real > 1_577_836_800_000_000_000,
            "realtime too small: {real}"
        );
    }

    #[test]
    fn pwrite_pread_round_trip() {
        let dir = test_dir("pwrite");
        let fd = open_dir_absolute(dir.path()).unwrap();
        let file = openat(
            fd.as_fd(),
            "blob",
            libc::O_CREAT | libc::O_RDWR | libc::O_CLOEXEC,
            0o600,
        )
        .unwrap();
        let data = b"hello-steadq";
        let n = pwrite(file.as_fd(), data, 0).unwrap();
        assert_eq!(n, data.len());
        fsync(file.as_fd()).unwrap();
        let mut buf = vec![0u8; data.len()];
        let r = pread(file.as_fd(), &mut buf, 0).unwrap();
        assert_eq!(r, data.len());
        assert_eq!(&buf, data);
    }

    #[test]
    fn linkat_tmpfile_publication_paths() {
        let dir = test_dir("tmpfile");
        let fd = open_dir_absolute(dir.path()).unwrap();
        // O_TMPFILE may be unsupported on some filesystems; skip if so.
        let tmp = match open_tmpfile(fd.as_fd()) {
            Ok(t) => t,
            Err(_) => return,
        };
        write_all(tmp.as_fd(), b"tmp").unwrap();
        // Prefer empty_path; fall back to proc path.
        let linked = linkat_empty_path(tmp.as_fd(), fd.as_fd(), "pub1")
            .or_else(|_| linkat_proc_self_fd(tmp.as_fd(), fd.as_fd(), "pub1"));
        assert!(linked.is_ok(), "tmpfile link failed: {linked:?}");
        assert!(fstatat(fd.as_fd(), "pub1").is_ok());
    }

    #[test]
    fn linkat_proc_self_fd_honors_fault_injection() {
        // empty_path may succeed first in the publication test and leave
        // linkat_proc_self_fd unexercised. Arm a fault so the real body runs.
        fault::reset();
        let dir = test_dir("linkat-proc-fault");
        let fd = open_dir_absolute(dir.path()).unwrap();
        let tmp = match open_tmpfile(fd.as_fd()) {
            Ok(t) => t,
            Err(_) => return,
        };
        fault::inject("linkat_proc_self_fd", 1);
        let err = linkat_proc_self_fd(tmp.as_fd(), fd.as_fd(), "pub-fault").unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EIO));
        fault::reset();
        // Real publication via proc path when empty_path is not used.
        linkat_proc_self_fd(tmp.as_fd(), fd.as_fd(), "pub-proc").unwrap();
        assert!(fstatat(fd.as_fd(), "pub-proc").is_ok());
    }
}
