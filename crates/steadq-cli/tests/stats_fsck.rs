// Integration tests for `steadq stats --prometheus` and `steadq fsck`.

use std::io::Write;
use std::process::Command;
use std::process::Stdio;

fn steadq() -> Command {
    Command::new(env!("CARGO_BIN_EXE_steadq"))
}

fn init_queue(dir: &std::path::Path) {
    let out = steadq()
        .args(["init", &dir.to_string_lossy()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn put_payload(dir: &std::path::Path, payload: &str) {
    let mut child = steadq()
        .args(["put", &dir.to_string_lossy(), "-"])
        .stdin(Stdio::piped())
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
    assert!(
        out.status.success(),
        "put failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn stats_prometheus_counts_objects() {
    let tmp = tempfile::tempdir().unwrap();
    init_queue(tmp.path());
    put_payload(tmp.path(), "one");
    put_payload(tmp.path(), "two");

    let out = steadq()
        .args(["stats", &tmp.path().to_string_lossy(), "--prometheus"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("steadq_ready_objects 2"), "got: {text}");
    // Every metric line follows the gauge type declaration.
    for line in text.lines().filter(|l| l.starts_with("steadq_")) {
        assert!(
            line.ends_with(|c: char| c.is_ascii_digit()),
            "metric line not numeric: {line}"
        );
    }
}

#[test]
fn fsck_clean_queue_exits_zero() {
    let tmp = tempfile::tempdir().unwrap();
    init_queue(tmp.path());
    put_payload(tmp.path(), "clean");

    let out = steadq()
        .args(["fsck", &tmp.path().to_string_lossy()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "fsck on clean queue failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("structurally verified: 1"), "got: {stderr}");
}

/// Path of the single ready job file in a freshly initialized queue.
fn ready_job_file(root: &std::path::Path) -> std::path::PathBuf {
    let ready = root.join("ready");
    for shard in std::fs::read_dir(&ready).unwrap().flatten() {
        let shard_path = shard.path();
        if let Ok(mut entries) = std::fs::read_dir(&shard_path) {
            if entries.next().is_some() {
                let mut file = None;
                for entry in std::fs::read_dir(&shard_path).unwrap().flatten() {
                    file = Some(entry.path());
                }
                return file.expect("shard entry is the job file");
            }
        }
    }
    panic!("no ready job file found under {}", ready.display());
}

/// Corrupt a job file's header magic so fsck reports an Error finding.
fn corrupt_header(path: &std::path::Path) {
    let mut data = std::fs::read(path).unwrap();
    data[0] ^= 0xFF;
    std::fs::write(path, data).unwrap();
}

#[test]
fn fsck_reports_corrupt_object_and_exits_corruption() {
    let tmp = tempfile::tempdir().unwrap();
    init_queue(tmp.path());
    put_payload(tmp.path(), "job");
    let job_file = ready_job_file(tmp.path());
    let job_name = job_file.file_name().unwrap().to_string_lossy().into_owned();
    corrupt_header(&job_file);

    let out = steadq()
        .args(["fsck", &tmp.path().to_string_lossy()])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(3),
        "corrupt queue must exit 3: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ERROR"), "got: {stdout}");
    assert!(stdout.contains(&job_name), "got: {stdout}");
}

#[test]
fn fsck_repair_quarantines_corrupt_object() {
    let tmp = tempfile::tempdir().unwrap();
    init_queue(tmp.path());
    put_payload(tmp.path(), "job");
    let job_file = ready_job_file(tmp.path());
    corrupt_header(&job_file);

    let out = steadq()
        .args(["fsck", &tmp.path().to_string_lossy(), "--repair"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("quarantined: 1"), "got: {stderr}");
    // Repair quarantined the corruption but the finding remains in the
    // report, so the exit still reports it: repair is not silent.
    assert_eq!(out.status.code(), Some(3));
    assert!(!job_file.exists());
    let q = count_recursive(&tmp.path().join("quarantine"));
    assert_eq!(q, 1);
}

fn count_recursive(path: &std::path::Path) -> usize {
    std::fs::read_dir(path)
        .map(|entries| {
            entries
                .flatten()
                .map(|e| {
                    let p = e.path();
                    if p.is_dir() {
                        count_recursive(&p)
                    } else {
                        1
                    }
                })
                .sum()
        })
        .unwrap_or(0)
}

#[test]
fn dead_admin_reports_a_missing_job_as_ordinary_failure() {
    let tmp = tempfile::tempdir().unwrap();
    init_queue(tmp.path());
    let root = tmp.path().to_string_lossy().into_owned();
    let job_id = "00".repeat(16);
    let output = tmp.path().join("out.bin").to_string_lossy().into_owned();
    for args in [
        vec!["admin", "dead-remove", &root, &job_id],
        vec!["admin", "dead-export", &root, &job_id, &output],
    ] {
        let out = steadq().args(&args).output().unwrap();
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("not found"));
    }
}
