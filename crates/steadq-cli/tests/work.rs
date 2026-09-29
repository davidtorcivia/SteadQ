// Integration tests for `steadq work` against the built binary.

use std::io::Write;
use std::process::{Command, Stdio};

fn steadq() -> Command {
    Command::new(env!("CARGO_BIN_EXE_steadq"))
}

fn init_queue(dir: &std::path::Path) {
    let out = steadq()
        .args(["init", &dir.to_string_lossy()])
        .output()
        .unwrap();
    assert!(out.status.success(), "init failed: {}", out_stderr(&out));
}

/// Enqueue `payload` and return its job id.
fn put_payload(dir: &std::path::Path, payload: &str) -> String {
    let mut child = steadq()
        .args(["put", &dir.to_string_lossy(), "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(payload.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "put failed: {}", out_stderr(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout.lines().find(|l| l.starts_with("job_id: ")).unwrap();
    line["job_id: ".len()..].to_string()
}

fn out_stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn work(dir: &std::path::Path, extra: &[&str], command: &[&str]) -> std::process::Output {
    let mut cmd = steadq();
    cmd.arg("work").arg(dir);
    for flag in extra {
        cmd.arg(flag);
    }
    // Explicit -- so commands may start with dashes.
    cmd.arg("--");
    for arg in command {
        cmd.arg(arg);
    }
    cmd.output().unwrap()
}

fn lease_is_empty(dir: &std::path::Path) -> bool {
    let out = steadq()
        .args(["lease", &dir.to_string_lossy()])
        .output()
        .unwrap();
    // Empty exits EXIT_ORDINARY with "no jobs available"; a lease exits 0.
    !out.status.success() && out_stderr(&out).contains("no jobs available")
}

#[test]
fn work_once_feeds_payload_on_stdin_and_acks() {
    let tmp = tempfile::tempdir().unwrap();
    init_queue(tmp.path());
    put_payload(tmp.path(), "hello work payload\n");

    let out = work(tmp.path(), &["--once"], &["cat"]);
    assert!(out.status.success(), "work failed: {}", out_stderr(&out));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "hello work payload\n");
    assert!(lease_is_empty(tmp.path()), "job was not acked");
}

#[test]
fn work_once_requeues_failing_job() {
    let tmp = tempfile::tempdir().unwrap();
    init_queue(tmp.path());
    put_payload(tmp.path(), "will fail\n");

    let out = work(tmp.path(), &["--once"], &["false"]);
    assert_eq!(out.status.code(), Some(1), "exit: {}", out_stderr(&out));

    // The job must be back in ready and leasable.
    let out = steadq()
        .args(["lease", &tmp.path().to_string_lossy()])
        .output()
        .unwrap();
    assert!(out.status.success(), "requeued job not leasable");
}

#[test]
fn work_renews_lease_for_long_job() {
    let tmp = tempfile::tempdir().unwrap();
    init_queue(tmp.path());
    put_payload(tmp.path(), "slow job\n");

    // 1 s lease, renewed at 500 ms, while the job sleeps 3 s. Without
    // renewal the ack would hit an expired lease and fail.
    let out = work(
        tmp.path(),
        &["--once", "--lease-seconds", "1"],
        &["sleep", "3"],
    );
    assert!(
        out.status.success(),
        "work with renewal failed: {}",
        out_stderr(&out)
    );
    assert!(lease_is_empty(tmp.path()), "slow job was not acked");
}

#[test]
fn work_once_on_empty_queue_exits_zero() {
    let tmp = tempfile::tempdir().unwrap();
    init_queue(tmp.path());

    let out = work(tmp.path(), &["--once"], &["cat"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "empty queue must exit 0: {}",
        out_stderr(&out)
    );
}

#[test]
fn work_once_feeds_payload_larger_than_pipe_capacity() {
    let tmp = tempfile::tempdir().unwrap();
    init_queue(tmp.path());
    let payload = "payload\n".repeat(32 * 1024);
    put_payload(tmp.path(), &payload);
    let out = work(tmp.path(), &["--once"], &["cat"]);
    assert!(out.status.success(), "work failed: {}", out_stderr(&out));
    assert_eq!(out.stdout, payload.as_bytes());
    assert!(lease_is_empty(tmp.path()));
}

#[test]
fn work_once_does_not_wait_for_descendant_holding_stdin() {
    let tmp = tempfile::tempdir().unwrap();
    init_queue(tmp.path());
    put_payload(tmp.path(), &"x".repeat(1024 * 1024));
    let pid_file = tmp.path().join("descendant.pid");
    let mut worker = steadq()
        .arg("work")
        .arg(tmp.path())
        .args(["--once", "--", "sh", "-c"])
        .arg("sleep 10 <&0 & echo $! > \"$1\"")
        .arg("worker")
        .arg(&pid_file)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let status = loop {
        if let Some(status) = worker.try_wait().unwrap() {
            break Some(status);
        }
        if std::time::Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    if status.is_none() {
        worker.kill().unwrap();
        worker.wait().unwrap();
    }
    let pid: i32 = std::fs::read_to_string(pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    unsafe { libc::kill(pid, libc::SIGKILL) };
    assert!(
        status.is_some(),
        "worker waited for descendant holding stdin"
    );
    assert!(status.unwrap().success());
    assert!(lease_is_empty(tmp.path()));
}

/// Lease the next job and return the stderr summary; panics if empty.
fn lease_summary(dir: &std::path::Path) -> String {
    let out = steadq()
        .args(["lease", &dir.to_string_lossy()])
        .output()
        .unwrap();
    assert!(out.status.success(), "lease failed: {}", out_stderr(&out));
    out_stderr(&out)
}

fn wait_for_file(path: &std::path::Path) -> String {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if let Ok(text) = std::fs::read_to_string(path) {
            if text.ends_with('\n') {
                return text.trim().to_string();
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{} never written",
            path.display()
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn wait_with_deadline(child: &mut std::process::Child, secs: u64) -> std::process::ExitStatus {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("process did not exit within {secs}s");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// True once `pid` is gone or a zombie: it no longer runs.
fn process_ended(pid: i32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Err(_) => true,
        Ok(stat) => stat
            .rsplit(')')
            .next()
            .is_some_and(|rest| rest.trim_start().starts_with('Z')),
    }
}

#[test]
fn work_with_missing_command_exits_127_before_leasing() {
    let tmp = tempfile::tempdir().unwrap();
    init_queue(tmp.path());
    put_payload(tmp.path(), "job\n");

    // Loop mode: without the pre-check this would requeue until buried.
    let mut worker = steadq()
        .arg("work")
        .arg(tmp.path())
        .args(["--", "steadq-no-such-command"])
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let status = wait_with_deadline(&mut worker, 10);
    assert_eq!(status.code(), Some(127));
    // No attempt was consumed.
    assert!(lease_summary(tmp.path()).contains("attempt: 1/3"));
}

#[test]
fn work_passes_job_id_and_attempt_to_the_child() {
    let tmp = tempfile::tempdir().unwrap();
    init_queue(tmp.path());
    let job_id = put_payload(tmp.path(), "job\n");
    let out = work(
        tmp.path(),
        &["--once"],
        &["sh", "-c", "echo \"$STEADQ_JOB_ID $STEADQ_ATTEMPT\""],
    );
    assert!(out.status.success(), "work failed: {}", out_stderr(&out));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("{job_id} 1\n")
    );
}

#[test]
fn work_once_reports_signalled_child_as_128_plus_signal() {
    let tmp = tempfile::tempdir().unwrap();
    init_queue(tmp.path());
    put_payload(tmp.path(), "job\n");
    let out = work(tmp.path(), &["--once"], &["sh", "-c", "kill -9 $$"]);
    assert_eq!(out.status.code(), Some(137), "{}", out_stderr(&out));
    assert!(lease_summary(tmp.path()).contains("attempt: 2/3"));
}

#[test]
fn work_child_dies_with_a_killed_worker() {
    let tmp = tempfile::tempdir().unwrap();
    init_queue(tmp.path());
    put_payload(tmp.path(), "job\n");
    let pid_file = tmp.path().join("child.pid");
    let mut worker = steadq()
        .arg("work")
        .arg(tmp.path())
        .args(["--once", "--", "sh", "-c"])
        .arg("echo $$ > \"$1\"; exec sleep 30")
        .arg("sh")
        .arg(&pid_file)
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let child: i32 = wait_for_file(&pid_file).parse().unwrap();
    worker.kill().unwrap();
    worker.wait().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !process_ended(child) {
        if std::time::Instant::now() >= deadline {
            unsafe { libc::kill(child, libc::SIGKILL) };
            panic!("child {child} outlived its worker");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn work_sigterm_stops_leasing_and_requeues_the_running_job() {
    let tmp = tempfile::tempdir().unwrap();
    init_queue(tmp.path());
    put_payload(tmp.path(), "job\n");
    let pid_file = tmp.path().join("child.pid");
    let mut worker = steadq()
        .arg("work")
        .arg(tmp.path())
        .args(["--", "sh", "-c"])
        .arg("echo $$ > \"$1\"; exec sleep 30")
        .arg("sh")
        .arg(&pid_file)
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_for_file(&pid_file);
    unsafe { libc::kill(worker.id() as i32, libc::SIGTERM) };
    let status = wait_with_deadline(&mut worker, 10);
    assert_eq!(status.code(), Some(0));
    // The forwarded SIGTERM failed the job, so it went back to ready.
    assert!(lease_summary(tmp.path()).contains("attempt: 2/3"));
}
