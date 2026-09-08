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

fn put_payload(dir: &std::path::Path, payload: &str) {
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
