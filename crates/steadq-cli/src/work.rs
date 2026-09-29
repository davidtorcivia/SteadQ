// Worker loop: lease a job, feed its payload to a command on stdin, renew
// the lease while the command runs, ack on exit 0, requeue on nonzero.
// A crash mid-job is covered by lease expiry: recovery reaps the lease and
// the job re-runs (at-least-once). The child gets SIGKILL through
// PR_SET_PDEATHSIG when the worker dies, so it cannot outlive its lease.

use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use steadq_core::{
    AckOutcome, Error, LeaseInfo, LeaseOutcome, OpenOptions, Queue, RenewOutcome,
    TransitionOutcome, TransitionTicket, VerifiedPayloadReader,
};

const CHUNK: usize = 64 * 1024;
const POLL: Duration = Duration::from_millis(50);
// Bounded wait between scans in loop mode; the lease() backoff paces inside.
const SCAN_WAIT_NS: u64 = 1_000_000_000;
// How often a running job checks for a stop request.
const STOP_POLL: Duration = Duration::from_millis(100);
const EXIT_NOT_FOUND: u8 = 127;

/// Set by SIGTERM/SIGINT or a spawn failure: workers lease no new jobs.
static STOP: AtomicBool = AtomicBool::new(false);
/// Set by SIGTERM/SIGINT only: running children get SIGTERM forwarded.
static SIGNALLED: AtomicBool = AtomicBool::new(false);
/// Exit code forced on the whole run by a spawn failure.
static FATAL: AtomicU8 = AtomicU8::new(0);

extern "C" fn on_stop_signal(signal: libc::c_int) {
    // A second signal exits at once; PDEATHSIG then kills the children.
    if SIGNALLED.swap(true, Ordering::SeqCst) {
        unsafe { libc::_exit(128 + signal) };
    }
    STOP.store(true, Ordering::SeqCst);
}

fn install_stop_handlers() {
    let handler = on_stop_signal as extern "C" fn(libc::c_int);
    for signal in [libc::SIGTERM, libc::SIGINT] {
        // glibc signal() installs with SA_RESTART.
        unsafe { libc::signal(signal, handler as libc::sighandler_t) };
    }
}

/// Resolve the command the way exec does: a name with a slash is a path,
/// otherwise the first executable regular file on PATH.
fn command_is_runnable(program: &str) -> bool {
    let executable = |path: &Path| {
        path.metadata()
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    };
    if program.contains('/') {
        return executable(Path::new(program));
    }
    !program.is_empty()
        && std::env::var_os("PATH").is_some_and(|paths| {
            std::env::split_paths(&paths).any(|dir| executable(&dir.join(program)))
        })
}

/// Lease errors that will not clear by waiting: the worker exits on these
/// and keeps polling on everything else.
fn lease_error_is_fatal(error: &Error) -> bool {
    matches!(
        error,
        Error::QueueCorrupt(_)
            | Error::PayloadCorrupt
            | Error::QueuePoisoned(_)
            | Error::PermissionDenied
            | Error::UnsupportedFilesystem
            | Error::UnsupportedFormat
            | Error::InvalidInput(_)
            | Error::InvalidTicket(_)
    )
}

/// Wait before the next renewal: half the lease after a success; after a
/// failure, retry every min(T/8, 1 s) so one transient error cannot run
/// the lease out.
fn renew_interval(lease_duration_ns: u64, last_failed: bool) -> Duration {
    if last_failed {
        Duration::from_nanos(lease_duration_ns / 8).min(Duration::from_secs(1))
    } else {
        Duration::from_nanos(lease_duration_ns / 2)
    }
}

/// Exit code for a failed child: its own code, or 128+N for signal N.
fn child_exit_code(status: ExitStatus) -> u8 {
    let code = status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1);
    code.clamp(1, 255) as u8
}

/// Print an indeterminate outcome with its ticket for `steadq resolve`.
fn report_unknown(operation: &str, ticket: &TransitionTicket) {
    eprintln!(
        "{operation} outcome unknown: job {}",
        steadq_names::hex_encode(&ticket.job_id())
    );
    if let Ok(json) = ticket.to_json() {
        eprintln!("ticket: {}", String::from_utf8_lossy(&json));
    }
}

pub fn run(
    path: &Path,
    concurrency: u32,
    lease_duration_ns: u64,
    once: bool,
    command: &[String],
) -> u8 {
    // Fail before leasing: a missing command would requeue every job until
    // its attempts ran out.
    if !command_is_runnable(&command[0]) {
        eprintln!("{}: command not found or not executable", command[0]);
        return EXIT_NOT_FOUND;
    }
    install_stop_handlers();
    let mut handles = Vec::new();
    for _ in 0..concurrency {
        let path = path.to_path_buf();
        let command = command.to_vec();
        handles.push(std::thread::spawn(move || {
            worker(path, lease_duration_ns, once, command)
        }));
    }
    let mut code = 0;
    for handle in handles {
        match handle.join() {
            Ok(c) => code = code.max(c),
            Err(_) => {
                eprintln!("worker thread panicked");
                code = code.max(1);
            }
        }
    }
    code.max(FATAL.load(Ordering::SeqCst))
}

fn worker(
    path: std::path::PathBuf,
    lease_duration_ns: u64,
    once: bool,
    command: Vec<String>,
) -> u8 {
    let mut queue = match Queue::open(
        &path,
        &OpenOptions {
            // Renewal barriers defer: ack and requeue sync the directory
            // themselves, so renewals cost a rename with no fsync.
            deferred_dir_sync: true,
            ..Default::default()
        },
    ) {
        Ok(q) => q,
        Err(e) => {
            eprintln!("open failed: {e}");
            return crate::core_exit_code(&e);
        }
    };
    loop {
        if STOP.load(Ordering::SeqCst) {
            return 0;
        }
        let wait_ns = if once { 0 } else { SCAN_WAIT_NS };
        let lease = match queue.lease(wait_ns, lease_duration_ns) {
            LeaseOutcome::Leased(lease) => lease,
            LeaseOutcome::Empty if once => return 0,
            LeaseOutcome::Empty => continue,
            LeaseOutcome::NotCommitted(e) => {
                eprintln!("lease failed: {e}");
                if once || lease_error_is_fatal(&e) {
                    return crate::core_exit_code(&e);
                }
                std::thread::sleep(Duration::from_nanos(SCAN_WAIT_NS));
                continue;
            }
            LeaseOutcome::OutcomeUnknown(ticket) => {
                report_unknown("lease", &ticket);
                return 2;
            }
        };
        // A signal during the lease wait: hand the job back unrun. The claim
        // already counted the attempt, so a last attempt runs instead of dying.
        if STOP.load(Ordering::SeqCst) && lease.attempt < lease.maximum_attempts {
            return requeue(&mut queue, &lease);
        }
        let code = run_one(&mut queue, lease, lease_duration_ns, &command);
        if once {
            return code;
        }
    }
}

fn run_one(
    queue: &mut Queue,
    mut lease: LeaseInfo,
    lease_duration_ns: u64,
    command: &[String],
) -> u8 {
    let reader = match queue.open_verified_payload_reader(&lease) {
        Ok(Some(reader)) => reader,
        Ok(None) => {
            eprintln!("lease source vanished");
            return 1;
        }
        Err(e) => {
            eprintln!("payload verification failed: {e}");
            return crate::core_exit_code(&e);
        }
    };

    let worker_pid = std::process::id() as libc::pid_t;
    let mut command_line = Command::new(&command[0]);
    command_line
        .args(&command[1..])
        .stdin(Stdio::piped())
        .env("STEADQ_JOB_ID", steadq_names::hex_encode(&lease.job_id))
        .env("STEADQ_ATTEMPT", lease.attempt.to_string());
    // PDEATHSIG fires when the spawning thread exits. This worker thread
    // blocks in babysit until the child is reaped, so it outlives the child.
    // The getppid check covers a worker that died before the prctl.
    // Async-signal-safe calls only: no allocation between fork and exec.
    unsafe {
        command_line.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != worker_pid {
                return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
            }
            Ok(())
        });
    }
    let mut child = match command_line.spawn() {
        Ok(child) => child,
        Err(e) => {
            // The command was checked before the first lease, so it vanished
            // or cannot exec. Requeue this job (one attempt consumed) and
            // stop, rather than burning every job's attempts the same way.
            eprintln!("spawn {} failed: {e}; stopping", command[0]);
            FATAL.fetch_max(EXIT_NOT_FOUND, Ordering::SeqCst);
            STOP.store(true, Ordering::SeqCst);
            return requeue(queue, &lease).max(EXIT_NOT_FOUND);
        }
    };

    let stdin = child.stdin.take().expect("piped stdin");
    let flags = unsafe { libc::fcntl(stdin.as_raw_fd(), libc::F_GETFL) };
    if flags == -1
        || unsafe { libc::fcntl(stdin.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1
    {
        eprintln!(
            "configure stdin failed: {}",
            std::io::Error::last_os_error()
        );
        let _ = child.kill();
        let _ = child.wait();
        return requeue(queue, &lease).max(6);
    }
    let stopped = AtomicBool::new(false);
    let (status, fed) = std::thread::scope(|scope| {
        let feeder = scope.spawn(|| feed(reader, stdin, &stopped));
        let status = babysit(queue, &mut lease, &mut child, lease_duration_ns);
        if status.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        stopped.store(true, Ordering::Relaxed);
        (status, feeder.join().unwrap_or(false))
    });

    match status {
        Ok(status) if status.success() && fed => finish(queue, &lease),
        Ok(status) if status.success() => {
            eprintln!("payload delivery failed; job requeued");
            requeue(queue, &lease).max(1)
        }
        Ok(status) => requeue(queue, &lease).max(child_exit_code(status)),
        Err(e) => {
            eprintln!("wait failed: {e}");
            6
        }
    }
}

/// Stop feeding when the direct child exits, even if a descendant retains stdin.
fn feed(
    reader: VerifiedPayloadReader,
    mut stdin: std::process::ChildStdin,
    stopped: &AtomicBool,
) -> bool {
    let mut buf = vec![0u8; CHUNK];
    let mut offset = 0u64;
    loop {
        let n = match reader.read_at(&mut buf, offset) {
            Ok(0) => return true,
            Ok(n) => n,
            Err(_) => return false,
        };
        let mut written = 0;
        while written < n {
            if stopped.load(Ordering::Relaxed) {
                return true;
            }
            match stdin.write(&buf[written..n]) {
                Ok(0) => return false,
                Ok(n) => written += n,
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => return true,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    let mut fd = libc::pollfd {
                        fd: stdin.as_raw_fd(),
                        events: libc::POLLOUT,
                        revents: 0,
                    };
                    let result = unsafe { libc::poll(&mut fd, 1, POLL.as_millis() as i32) };
                    if result < 0
                        && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
                    {
                        return false;
                    }
                }
                Err(_) => return false,
            }
        }
        offset += n as u64;
    }
}

/// Wait for the child while renewing the lease on the `renew_interval`
/// schedule. When renewal stops (lost or unknown), the child still
/// finishes; the closing ack reports the loss. A stop request forwards
/// SIGTERM to the child once; its exit then requeues or acks as usual.
fn babysit(
    queue: &mut Queue,
    lease: &mut LeaseInfo,
    child: &mut Child,
    lease_duration_ns: u64,
) -> std::io::Result<ExitStatus> {
    let pid = child.id() as libc::pid_t;
    std::thread::scope(|scope| {
        let (sender, receiver) = mpsc::sync_channel(1);
        scope.spawn(move || {
            let _ = sender.send(child.wait());
        });
        let mut renewing = true;
        let mut forwarded = false;
        let mut next_renew = Instant::now() + renew_interval(lease_duration_ns, false);
        loop {
            let wait = next_renew
                .saturating_duration_since(Instant::now())
                .min(STOP_POLL);
            match receiver.recv_timeout(wait) {
                Ok(status) => return status,
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(std::io::Error::other("child wait thread disconnected"));
                }
                Err(RecvTimeoutError::Timeout) => {}
            }
            if !forwarded && SIGNALLED.load(Ordering::SeqCst) {
                forwarded = true;
                // ponytail: kill by pid races the reap in the wait thread; a
                // pidfd closes that if pid reuse within 100 ms ever matters.
                unsafe { libc::kill(pid, libc::SIGTERM) };
            }
            if !renewing || Instant::now() < next_renew {
                continue;
            }
            let failed = match queue.renew(lease, lease_duration_ns) {
                RenewOutcome::Renewed(fresh) | RenewOutcome::Deferred(fresh) => {
                    *lease = fresh;
                    false
                }
                RenewOutcome::LeaseLost => {
                    eprintln!("lease lost; letting the job finish without renewal");
                    renewing = false;
                    false
                }
                RenewOutcome::NotCommitted(e) => {
                    eprintln!("renew failed: {e}; retrying");
                    true
                }
                RenewOutcome::OutcomeUnknown(ticket) => {
                    report_unknown("renew", &ticket);
                    renewing = false;
                    false
                }
            };
            next_renew = Instant::now() + renew_interval(lease_duration_ns, failed);
        }
    })
}

/// Acknowledge a finished job. Exit 0 on ack; the ack's own outcome decides
/// everything else.
fn finish(queue: &mut Queue, lease: &LeaseInfo) -> u8 {
    match queue.ack(lease) {
        AckOutcome::Acked | AckOutcome::AlreadyAcked => 0,
        AckOutcome::LeaseLost => {
            eprintln!("lease lost");
            1
        }
        AckOutcome::NotCommitted(e) => {
            eprintln!("ack not committed: {e}");
            crate::core_exit_code(&e)
        }
        AckOutcome::OutcomeUnknown(ticket) => {
            report_unknown("ack", &ticket);
            2
        }
    }
}

/// Return a failed job to ready; the library routes exhausted attempts to
/// dead.
fn requeue(queue: &mut Queue, lease: &LeaseInfo) -> u8 {
    match queue.retry_now(lease) {
        TransitionOutcome::Committed => 0,
        TransitionOutcome::LeaseLost => {
            eprintln!("lease lost");
            1
        }
        TransitionOutcome::NotCommitted(e) => {
            eprintln!("retry not committed: {e}");
            crate::core_exit_code(&e)
        }
        TransitionOutcome::OutcomeUnknown(ticket) => {
            report_unknown("retry", &ticket);
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renew_interval_retries_quickly_after_a_failure() {
        let s = 1_000_000_000u64;
        for (lease_ns, failed, expected) in [
            (60 * s, false, Duration::from_secs(30)),
            (60 * s, true, Duration::from_secs(1)),
            (4 * s, true, Duration::from_millis(500)),
            (s, false, Duration::from_millis(500)),
            (s, true, Duration::from_millis(125)),
        ] {
            assert_eq!(
                renew_interval(lease_ns, failed),
                expected,
                "{lease_ns} {failed}"
            );
        }
        // One failure at T/2 still leaves many retries before expiry.
        let t = 60 * s;
        let retries_before_expiry = (Duration::from_nanos(t) - renew_interval(t, false)).as_nanos()
            / renew_interval(t, true).as_nanos();
        assert!(retries_before_expiry >= 10, "{retries_before_expiry}");
    }

    #[test]
    fn only_non_transient_lease_errors_stop_the_worker() {
        for fatal in [
            Error::QueueCorrupt("x".into()),
            Error::PayloadCorrupt,
            Error::QueuePoisoned("x".into()),
            Error::PermissionDenied,
            Error::UnsupportedFilesystem,
            Error::UnsupportedFormat,
            Error::InvalidInput("x".into()),
            Error::InvalidTicket("x".into()),
        ] {
            assert!(lease_error_is_fatal(&fatal), "{fatal:?}");
        }
        for transient in [
            Error::MaintenanceBusy,
            Error::IoFailure("x".into()),
            Error::ResourceExhausted,
            Error::StateExhausted,
            Error::InvalidClock,
            Error::IdentityCollision,
        ] {
            assert!(!lease_error_is_fatal(&transient), "{transient:?}");
        }
    }

    #[test]
    fn command_resolution_matches_exec() {
        assert!(command_is_runnable("sh"));
        assert!(command_is_runnable("/bin/sh"));
        assert!(!command_is_runnable("steadq-no-such-command"));
        assert!(!command_is_runnable("/nonexistent/sh"));
        assert!(!command_is_runnable(""));
        // A directory is not a command.
        assert!(!command_is_runnable("/"));
        // A regular file without an execute bit is not a command.
        let file = tempfile::NamedTempFile::new().unwrap();
        assert!(!command_is_runnable(file.path().to_str().unwrap()));
    }

    #[test]
    fn signalled_child_exits_128_plus_signal() {
        assert_eq!(child_exit_code(ExitStatus::from_raw(9)), 137);
        assert_eq!(child_exit_code(ExitStatus::from_raw(3 << 8)), 3);
    }
}
