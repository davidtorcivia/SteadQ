// Integration tests for lease handles, bench, stats, doctor, verify, bury,
// and admin compact-receipts against the built binary.

use std::io::Write;
use std::process::{Command, Output, Stdio};

fn steadq() -> Command {
    Command::new(env!("CARGO_BIN_EXE_steadq"))
}

fn run(args: &[&std::ffi::OsStr]) -> Output {
    steadq().args(args).output().unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn init_queue(dir: &std::path::Path) {
    let out = run(&["init".as_ref(), dir.as_os_str()]);
    assert!(out.status.success(), "init failed: {}", stderr(&out));
}

fn put_payload(dir: &std::path::Path, payload: &str) {
    let mut child = steadq()
        .arg("put")
        .arg(dir)
        .arg("-")
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
    assert!(out.status.success(), "put failed: {}", stderr(&out));
}

fn stats_json(dir: &std::path::Path) -> serde_json::Value {
    let out = run(&["stats".as_ref(), dir.as_os_str(), "--json".as_ref()]);
    assert!(out.status.success(), "stats failed: {}", stderr(&out));
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn lease_without_handle_file_prints_a_usable_handle() {
    let tmp = tempfile::tempdir().unwrap();
    let queue = tmp.path().join("q");
    init_queue(&queue);
    put_payload(&queue, "job");

    let out = run(&["lease".as_ref(), queue.as_os_str()]);
    assert!(out.status.success(), "lease failed: {}", stderr(&out));
    assert!(stderr(&out).contains("attempt: 1/3"));
    let handle = tmp.path().join("handle.json");
    std::fs::write(&handle, &out.stdout).unwrap();

    let out = run(&[
        "ack".as_ref(),
        queue.as_os_str(),
        "--handle-file".as_ref(),
        handle.as_os_str(),
    ]);
    assert!(out.status.success(), "ack failed: {}", stderr(&out));
}

#[test]
fn handle_file_for_another_root_or_truncated_exits_1() {
    let tmp = tempfile::tempdir().unwrap();
    let queue = tmp.path().join("q");
    init_queue(&queue);
    put_payload(&queue, "job");
    let handle = tmp.path().join("handle.json");
    let out = run(&[
        "lease".as_ref(),
        queue.as_os_str(),
        "--handle-file".as_ref(),
        handle.as_os_str(),
    ]);
    assert!(out.status.success(), "lease failed: {}", stderr(&out));
    let text = std::fs::read_to_string(&handle).unwrap();
    let ack = || {
        run(&[
            "ack".as_ref(),
            queue.as_os_str(),
            "--handle-file".as_ref(),
            handle.as_os_str(),
        ])
    };

    let mut moved: serde_json::Value = serde_json::from_str(&text).unwrap();
    moved["queue_root"] = tmp.path().to_string_lossy().into_owned().into();
    std::fs::write(&handle, moved.to_string()).unwrap();
    let out = ack();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("issued for the queue at"));

    std::fs::write(&handle, &text[..text.len() / 2]).unwrap();
    let out = ack();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("invalid handle file"));

    // The untouched handle still acks.
    std::fs::write(&handle, &text).unwrap();
    assert!(ack().status.success());
}

#[test]
fn bury_rejects_an_unknown_reason() {
    let tmp = tempfile::tempdir().unwrap();
    let out = run(&[
        "bury".as_ref(),
        tmp.path().as_os_str(),
        "--handle-file".as_ref(),
        tmp.path().join("h.json").as_os_str(),
        "--reason".as_ref(),
        "65537".as_ref(),
    ]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("consumer_rejected"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn stats_counts_a_live_lease_as_leased_not_ready() {
    let tmp = tempfile::tempdir().unwrap();
    init_queue(tmp.path());
    put_payload(tmp.path(), "one");
    put_payload(tmp.path(), "two");
    let out = run(&["lease".as_ref(), tmp.path().as_os_str()]);
    assert!(out.status.success(), "lease failed: {}", stderr(&out));

    let stats = stats_json(tmp.path());
    assert_eq!(stats["ready"]["objects"], 1, "{stats}");
    assert_eq!(stats["leased"]["objects"], 1, "{stats}");
}

#[test]
fn bench_refuses_a_queue_holding_jobs() {
    let tmp = tempfile::tempdir().unwrap();
    init_queue(tmp.path());
    put_payload(tmp.path(), "real job");
    let bench = |extra: &[&str]| {
        let mut cmd = steadq();
        cmd.arg("bench")
            .arg(tmp.path())
            .args(["--duration-seconds", "0", "--producers", "0"])
            .args(extra);
        cmd.output().unwrap()
    };

    let out = bench(&[]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("--allow-nonempty"));
    assert_eq!(stats_json(tmp.path())["ready"]["objects"], 1);

    let out = bench(&["--allow-nonempty"]);
    assert!(out.status.success(), "{}", stderr(&out));
}

#[test]
fn doctor_on_an_unsupported_filesystem_exits_unsupported() {
    let out = run(&["doctor".as_ref(), "/proc".as_ref()]);
    assert_eq!(out.status.code(), Some(64), "{}", stderr(&out));
}

#[test]
fn verify_prints_fields_on_stdout() {
    let tmp = tempfile::tempdir().unwrap();
    init_queue(tmp.path());
    let out = run(&["verify".as_ref(), tmp.path().join("FORMAT").as_os_str()]);
    assert!(out.status.success(), "{}", stderr(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("type: format"), "{stdout}");
    assert!(stderr(&out).contains("valid"));
}

#[test]
fn compact_receipts_runs_recovery_to_completion() {
    let tmp = tempfile::tempdir().unwrap();
    init_queue(tmp.path());
    put_payload(tmp.path(), "job");
    let out = run(&[
        "admin".as_ref(),
        "compact-receipts".as_ref(),
        tmp.path().as_os_str(),
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stderr(&out).contains("compacted: 0"), "{}", stderr(&out));
}

#[test]
fn compact_receipts_exits_io_failure_on_recovery_errors() {
    use std::os::unix::fs::PermissionsExt;
    if unsafe { libc::geteuid() } == 0 {
        return; // root ignores the permission bits this test relies on
    }
    let tmp = tempfile::tempdir().unwrap();
    init_queue(tmp.path());
    put_payload(tmp.path(), "job");
    let handle = tmp.path().join("handle.json");
    let lease = run(&[
        "lease".as_ref(),
        tmp.path().as_os_str(),
        "--handle-file".as_ref(),
        handle.as_os_str(),
    ]);
    assert!(lease.status.success(), "{}", stderr(&lease));
    let ack = run(&[
        "ack".as_ref(),
        tmp.path().as_os_str(),
        "--handle-file".as_ref(),
        handle.as_os_str(),
    ]);
    assert!(ack.status.success(), "{}", stderr(&ack));
    let bucket = std::fs::read_dir(tmp.path().join("receipts"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let set_mode =
        |mode| std::fs::set_permissions(&bucket, std::fs::Permissions::from_mode(mode)).unwrap();
    set_mode(0o000);
    let out = run(&[
        "admin".as_ref(),
        "compact-receipts".as_ref(),
        tmp.path().as_os_str(),
    ]);
    set_mode(0o755);
    assert_eq!(out.status.code(), Some(6), "{}", stderr(&out));
    assert!(stderr(&out).contains("recovery errors"), "{}", stderr(&out));
}
