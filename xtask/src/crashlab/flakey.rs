// dm-flakey power-cut lane.
//
// Runs the concurrent workload (crashlab-concurrent) on ext4 over a
// dm-flakey target and, at a random point, appends a cut marker to the
// off-device op log and switches the table to drop (or fail) every later
// write. Writes that reached the device before the switch survive; page
// cache contents that were never written back are lost, which is what a
// power cut does to unsynced data. The workload keeps running briefly past
// the cut (its post-cut "successes" are lies the checker must not trust),
// then is killed; the filesystem is unmounted, the device recreated with
// the pass-through table, remounted (journal replay), and checked by
// crashlab-check against the lines before the marker.
//
// Unlike tier 1 this does not enumerate every crash state; it samples live
// multi-threaded kernel states that a single-threaded write log does not
// reach. Requires root. Same device guards as tier 1.

use super::guards;
use super::registry::{self, RegistryRun};
use super::tier1::{
    allocate_image, attach_loop, is_root, kernel_version, sectors_of, teardown_run_resources,
    umount_if_mounted, umount_retry,
};
use super::{ensure_bins, now_iso, run_cmd, write_json};
use serde_json::json;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

struct Args {
    cuts: u64,
    seed: u64,
    workers: u64,
    size_mb: u64,
    store: PathBuf,
    mode: String,
    mount_opts: String,
    min_ops: u64,
    max_ops: u64,
}

pub fn run(root: &Path, args: &[String]) -> Result<(), String> {
    let mut a = Args {
        cuts: 20,
        seed: 1,
        workers: 4,
        size_mb: 1024,
        store: PathBuf::from("/dev/shm/crashlab"),
        mode: "drop_writes".into(),
        mount_opts: String::new(),
        min_ops: 20,
        max_ops: 2000,
    };
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let value = it
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        let number = || value.parse::<u64>().map_err(|_| format!("bad {flag}"));
        match flag.as_str() {
            "--cuts" => a.cuts = number()?,
            "--seed" => a.seed = number()?,
            "--workers" => a.workers = number()?,
            "--size-mb" => a.size_mb = number()?,
            "--min-ops" => a.min_ops = number()?,
            "--max-ops" => a.max_ops = number()?,
            "--store" => a.store = PathBuf::from(value),
            "--mode" => a.mode = value.clone(),
            "--mount-opts" => a.mount_opts = value.clone(),
            _ => return Err(format!("unknown flag {flag}")),
        }
    }
    if !matches!(a.mode.as_str(), "drop_writes" | "error_writes") {
        return Err("--mode must be drop_writes or error_writes".into());
    }
    if a.min_ops == 0 || a.max_ops < a.min_ops {
        return Err("need 0 < --min-ops <= --max-ops".into());
    }
    if !is_root() {
        return Err("flakey needs root (losetup/dmsetup/mount); run under sudo".into());
    }
    if !guards::store_path_allowed(&a.store, root) {
        return Err(format!(
            "g1: store {} is not an allowed crash-lab store",
            a.store.display()
        ));
    }
    std::fs::create_dir_all(&a.store).map_err(|e| format!("store: {e}"))?;
    // Built-in or module; a failure here surfaces at the first dmsetup create.
    let _ = run_cmd("modprobe", &["dm-flakey"], &[]);
    let (_, check) = ensure_bins(root)?;
    let workload = check.with_file_name("crashlab-concurrent");

    let id = format!("fl-{}", std::process::id());
    let backing = a.store.join(format!("{id}.img"));
    let mount_dir = PathBuf::from(format!("/mnt/crashlab-{id}"));
    let dm_name = format!("crashlab-{id}");
    let mut run = RegistryRun {
        id: id.clone(),
        kind: "flakey".into(),
        backing: Some(backing.display().to_string()),
        marker: None,
        loops: Vec::new(),
        dm_names: vec![dm_name.clone()],
        mount: Some(mount_dir.display().to_string()),
        pool: None,
        status: "active".into(),
        started: now_iso(),
        ended: None,
    };
    registry::upsert(&a.store, &run)?;
    let result = execute(
        root, &a, &workload, &check, &id, &backing, &mount_dir, &dm_name, &mut run,
    );
    run.status = if result.is_ok() { "done" } else { "failed" }.into();
    run.ended = Some(now_iso());
    registry::upsert(&a.store, &run)?;
    teardown_run_resources(&run);
    if result.is_ok() {
        let _ = std::fs::remove_file(&backing);
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn execute(
    root: &Path,
    a: &Args,
    workload: &Path,
    check: &Path,
    id: &str,
    backing: &Path,
    mount_dir: &Path,
    dm_name: &str,
    run: &mut RegistryRun,
) -> Result<(), String> {
    allocate_image(backing, a.size_mb)?;
    let loop_dev = attach_loop(backing)?;
    run.loops = vec![loop_dev.clone()];
    registry::upsert(&a.store, run)?;
    guards::verify_block_target(&loop_dev, backing, root)?;
    let sectors = sectors_of(&loop_dev)?;
    // xfstests' flakey tables: pass everything, or drop/fail every write.
    let allow = format!("0 {sectors} flakey {loop_dev} 0 180 0");
    let cut = format!("0 {sectors} flakey {loop_dev} 0 0 180 1 {}", a.mode);
    let dm_node = format!("/dev/mapper/{dm_name}");
    std::fs::create_dir_all(mount_dir).map_err(|e| format!("mkdir mount: {e}"))?;
    let mount_dir_str = mount_dir.to_string_lossy().into_owned();
    let mount = || {
        let mut args = vec![];
        if !a.mount_opts.is_empty() {
            args.extend(["-o", a.mount_opts.as_str()]);
        }
        args.extend([dm_node.as_str(), mount_dir_str.as_str()]);
        run_cmd("mount", &args, &[])
    };
    let queue_dir = mount_dir.join("queue");
    let queue_str = queue_dir.to_str().ok_or("queue path not utf-8")?;

    let mut rng = a.seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut verdicts = Vec::new();
    let mut after_cut_ops = std::collections::BTreeMap::<String, u64>::new();
    for cut_index in 0..a.cuts {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        let target = a.min_ops + rng % (a.max_ops - a.min_ops + 1);
        let tag = format!("{id}-c{cut_index}");
        let oplog = a.store.join(format!("{tag}.oplog"));
        let verdict_path = a.store.join(format!("{tag}.verdict.json"));
        let _ = std::fs::remove_file(&oplog);

        run_cmd("mkfs.ext4", &["-q", "-F"], &[&loop_dev])?;
        run_cmd("dmsetup", &["create", dm_name, "--table", &allow], &[])?;
        mount()?;
        let mut child = std::process::Command::new(workload)
            .args(["--queue", queue_str])
            .args(["--oplog", oplog.to_str().ok_or("oplog path not utf-8")?])
            .args(["--workers", &a.workers.to_string()])
            .args(["--seed", &(a.seed + cut_index).to_string()])
            .spawn()
            .map_err(|e| format!("spawn workload: {e}"))?;
        let started = Instant::now();
        let observed = loop {
            let lines = std::fs::read_to_string(&oplog)
                .map(|t| t.matches('\n').count() as u64)
                .unwrap_or(0);
            if lines >= target {
                break lines;
            }
            if let Ok(Some(status)) = child.try_wait() {
                return Err(format!("{tag}: workload exited early: {status}"));
            }
            if started.elapsed() > Duration::from_secs(300) {
                let _ = child.kill();
                return Err(format!("{tag}: workload reached {lines}/{target} ops"));
            }
            std::thread::sleep(Duration::from_micros(200));
        };

        // The marker goes in before the switch: every line above it
        // returned before any write was dropped. --nolockfs: no filesystem
        // freeze, so nothing is flushed on the way into the cut.
        let cut_result = std::fs::OpenOptions::new()
            .append(true)
            .open(&oplog)
            .and_then(|mut f| f.write_all(b"{\"op\":\"cut\"}\n"))
            .map_err(|e| format!("{tag}: cut marker: {e}"))
            .and_then(|()| run_cmd("dmsetup", &["suspend", "--nolockfs", dm_name], &[]))
            .and_then(|_| {
                run_cmd("dmsetup", &["load", dm_name, "--table", &cut], &[])
                    .and_then(|_| run_cmd("dmsetup", &["resume", dm_name], &[]))
                    .inspect_err(|_| {
                        // Suspended with a failed load or resume: resume the
                        // live table, or the workload's I/O never completes
                        // and the kill below waits forever.
                        let _ = run_cmd("dmsetup", &["resume", dm_name], &[]);
                    })
            });
        if cut_result.is_ok() {
            std::thread::sleep(Duration::from_millis(100 + rng % 200));
        }
        let _ = child.kill();
        let _ = child.wait();
        cut_result?;

        // Removing the device drops its page cache, so the remount reads
        // only what reached the loop image before the cut.
        umount_retry(mount_dir)?;
        dmsetup_remove(dm_name)?;
        run_cmd("dmsetup", &["create", dm_name, "--table", &allow], &[])?;
        let pass = match mount() {
            Ok(_) => {
                let status = std::process::Command::new(check)
                    .args(["--queue", queue_str])
                    .args(["--oplog", oplog.to_str().ok_or("oplog path not utf-8")?])
                    .args(["--out", verdict_path.to_str().ok_or("verdict path")?])
                    .stdout(std::process::Stdio::null())
                    .status()
                    .map_err(|e| format!("spawn checker: {e}"))?;
                umount_retry(mount_dir)?;
                status.success()
            }
            Err(e) => {
                write_json(&verdict_path, &json!({"pass": false, "mount_error": e}))?;
                false
            }
        };
        umount_if_mounted(mount_dir);
        dmsetup_remove(dm_name)?;

        let text = std::fs::read_to_string(&oplog).unwrap_or_default();
        let mut after = false;
        for line in text.lines() {
            if line.contains("\"op\":\"cut\"") {
                after = true;
            } else if after {
                if let Some(op) = line
                    .split("\"op\":\"")
                    .nth(1)
                    .and_then(|r| r.split('"').next())
                {
                    *after_cut_ops.entry(op.to_string()).or_default() += 1;
                }
            }
        }
        let verdict: serde_json::Value = std::fs::read_to_string(&verdict_path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or(json!({"pass": false, "missing_verdict": true}));
        eprintln!(
            "flakey {}/{} target={target} before_cut={} committed={} acked={} {}",
            cut_index + 1,
            a.cuts,
            verdict["ops_before_cut"],
            verdict["committed"],
            verdict["acked"],
            if pass { "PASS" } else { "FAIL" }
        );
        verdicts
            .push(json!({"cut": cut_index, "target": target, "observed": observed, "pass": pass}));
        if pass {
            let _ = std::fs::remove_file(&oplog);
            let _ = std::fs::remove_file(&verdict_path);
        } else {
            // Keep the image and op log for reproduction; stop at the first
            // violation.
            let kept = a.store.join(format!("{tag}.img"));
            let _ = std::process::Command::new("cp")
                .args(["--sparse=always"])
                .arg(backing)
                .arg(&kept)
                .status();
            return Err(format!(
                "flakey: cut {cut_index} FAILED; verdict {}, op log {}, image {}",
                verdict_path.display(),
                oplog.display(),
                kept.display()
            ));
        }
    }
    let summary = json!({
        "id": id,
        "mode": a.mode,
        "mount_opts": a.mount_opts,
        "workers": a.workers,
        "seed": a.seed,
        "kernel": kernel_version(),
        "cuts": a.cuts,
        "ops_after_cut_by_type": after_cut_ops,
        "verdicts": verdicts,
        "pass": true,
    });
    write_json(&a.store.join(format!("{id}.summary.json")), &summary)?;
    eprintln!(
        "flakey {}: {} cuts, all passed; ops in flight past the cut: {:?}",
        a.mode, a.cuts, after_cut_ops
    );
    Ok(())
}

/// Remove the dm device, retrying while the kernel releases the last opener.
fn dmsetup_remove(name: &str) -> Result<(), String> {
    let mut last = String::new();
    for _ in 0..50 {
        match run_cmd("dmsetup", &["remove", name], &[]) {
            Ok(_) => return Ok(()),
            Err(e) => last = e,
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(last)
}
