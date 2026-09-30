// Tier 1: dm-log-writes exhaustive crash replay.
//
// Records every block write (with fsync/FUA/discard marks) issued by a real
// workload on a real filesystem, then replays the log at every persistence
// barrier and checks each resulting crash state with the checker. Coverage is
// exhaustive over reachable crash states, not sampled.
//
// Requires root. Only touches loop devices this run created, over image
// files under an allowlisted store (guards g1-g4, see guards.rs).

use super::guards;
use super::registry::{self, RegistryRun};
use super::{ensure_bins, now_iso, run_cmd, write_json};
use serde_json::json;
use std::path::{Path, PathBuf};

struct T1Args {
    fs: String,
    ops: u64,
    seed: u64,
    size_mb: u64,
    store: PathBuf,
    max_marks: usize,
    keep_images: bool,
}

pub fn run(root: &Path, args: &[String]) -> Result<(), String> {
    let mut a = T1Args {
        fs: String::new(),
        ops: 40,
        seed: 1,
        size_mb: 8192,
        store: PathBuf::from("/dev/shm/crashlab"),
        max_marks: 0,
        keep_images: false,
    };
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let value = it
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag.as_str() {
            "--fs" => a.fs = value.clone(),
            "--ops" => a.ops = value.parse().map_err(|_| "bad --ops")?,
            "--seed" => a.seed = value.parse().map_err(|_| "bad --seed")?,
            "--size-mb" => a.size_mb = value.parse().map_err(|_| "bad --size-mb")?,
            "--store" => a.store = PathBuf::from(value),
            "--max-marks" => a.max_marks = value.parse().map_err(|_| "bad --max-marks")?,
            "--keep-images" => {
                a.keep_images = true;
                continue;
            }
            _ => return Err(format!("unknown flag {flag}")),
        }
    }
    match a.fs.as_str() {
        "ext4" | "xfs" | "btrfs" | "f2fs" | "zfs" => {}
        _ => return Err("tier1 requires --fs ext4|xfs|btrfs|f2fs|zfs".into()),
    }

    // Root check with a clear message (guards still protect without it).
    if !is_root() {
        return Err("tier1 needs root (losetup/dmsetup/mount); run under sudo. Device guards stay on either way.".into());
    }
    preflight(&a.fs)?;
    if !guards::store_path_allowed(&a.store, root) {
        return Err(format!(
            "g1: store {} is not an allowed crash-lab store",
            a.store.display()
        ));
    }
    std::fs::create_dir_all(&a.store).map_err(|e| format!("store: {e}"))?;
    print_preflight_device_map();

    let (workload, check) = ensure_bins(root)?;

    let id = format!("t1-{}-{}", a.fs, std::process::id());
    let backing = a.store.join(format!("{id}.img"));
    let marker = a.store.join(format!("{id}-log.img"));
    let oplog = a.store.join(format!("{id}.oplog"));
    let mount_dir = PathBuf::from(format!("/mnt/crashlab-{id}"));

    let mut run = RegistryRun {
        id: id.clone(),
        kind: "tier1".into(),
        backing: Some(backing.display().to_string()),
        marker: Some(marker.display().to_string()),
        loops: Vec::new(),
        dm_names: Vec::new(),
        mount: Some(mount_dir.display().to_string()),
        // Same construction as execute_run's pool_name.
        pool: (a.fs == "zfs").then(|| format!("crashl{}", std::process::id())),
        status: "active".into(),
        started: now_iso(),
        ended: None,
    };
    registry::upsert(&a.store, &run)?;

    let result = execute_run(
        root, &a, &workload, &check, &id, &backing, &marker, &oplog, &mount_dir, &mut run,
    );

    run.status = match &result {
        Ok(()) => "done".into(),
        Err(_) => "failed".into(),
    };
    run.ended = Some(now_iso());
    registry::upsert(&a.store, &run)?;
    teardown_run_resources(&run);
    if !a.keep_images && result.is_ok() {
        let _ = std::fs::remove_file(&backing);
        let _ = std::fs::remove_file(&marker);
        let _ = std::fs::remove_file(a.store.join(format!("{id}.pristine.img")));
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn execute_run(
    root: &Path,
    a: &T1Args,
    workload: &Path,
    check: &Path,
    id: &str,
    backing: &Path,
    marker: &Path,
    oplog: &Path,
    mount_dir: &Path,
    run: &mut RegistryRun,
) -> Result<(), String> {
    // 1. Backing + marker images.
    allocate_image(backing, a.size_mb)?;
    allocate_image(marker, 64)?;
    guards::store_path_allowed(backing, root)
        .then_some(())
        .ok_or_else(|| format!("g1: {}", backing.display()))?;

    // 2. Attach loops: backing, then marker.
    let loop_b = attach_loop(backing)?;
    let loop_m = attach_loop(marker)?;
    run.loops = vec![loop_b.clone(), loop_m.clone()];
    registry::upsert(&a.store, run)?;
    guards::verify_block_target(&loop_b, backing, root)?;
    guards::verify_block_target(&loop_m, marker, root)?;

    // 3. Filesystem with recorded options. ZFS has no pre-creation step:
    // the pool is created on the dm target in step 5 so the write log
    // records pool creation, and the pristine snapshot in step 4 is the
    // zeroed image.
    let is_zfs = a.fs == "zfs";
    let pool_name = format!("crashl{}", std::process::id());
    let mkfs_opts: &[&str] = match a.fs.as_str() {
        "ext4" => &["-b", "4096", "-F"],
        "xfs" => &["-f"],
        "btrfs" => &["-f"],
        "f2fs" => &["-f"],
        "zfs" => &[],
        _ => unreachable!(),
    };
    if !is_zfs {
        run_cmd(&format!("mkfs.{}", a.fs), mkfs_opts, &[&loop_b])
            .map_err(|e| format!("mkfs: {e}"))?;
    }
    let mkfs_version = if is_zfs {
        std::process::Command::new("zfs")
            .arg("version")
            .output()
            .map(|o| {
                format!(
                    "{}{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                )
            })
            .unwrap_or_default()
    } else {
        std::process::Command::new(format!("mkfs.{}", a.fs))
            .arg("-V")
            .output()
            .map(|o| {
                format!(
                    "{}{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                )
            })
            .unwrap_or_default()
    };

    // 4. dm log-writes target over the fresh fs.
    // Snapshot the pristine post-mkfs state: replay-log applies log entries
    // onto the backing image, so each crash state must start from the exact
    // pre-log image, not the final workload state.
    let pristine = a.store.join(format!("{id}.pristine.img"));
    copy_sparse(backing, &pristine)?;
    let sectors = sectors_of(&loop_b)?;
    let dm_name = format!("crashlab-{id}");
    run.dm_names = vec![dm_name.clone()];
    registry::upsert(&a.store, run)?;
    let table = format!("0 {sectors} log-writes {loop_b} {loop_m}");
    run_cmd("dmsetup", &["create", &dm_name, "--table", &table], &[])?;
    let dm_node = format!("/dev/mapper/{dm_name}");

    // 5. Bring up the filesystem, run the workload, quiesce.
    std::fs::create_dir_all(mount_dir).map_err(|e| format!("mkdir mount: {e}"))?;
    let mount_dir_str = mount_dir.to_string_lossy().into_owned();
    if is_zfs {
        // cachefile=none keeps the run's pool out of the host cache; the
        // crash states below import with the same flag. Creation happens on
        // the dm target so the log records it.
        run_cmd(
            "zpool",
            &[
                "create",
                "-f",
                "-o",
                "ashift=12",
                "-o",
                "cachefile=none",
                "-m",
                &mount_dir_str,
                &pool_name,
                &dm_node,
            ],
            &[],
        )
        .map_err(|e| format!("zpool create: {e}"))?;
    } else {
        run_cmd("mount", &[&dm_node, &mount_dir_str], &[])?;
    }
    let mount_info = if is_zfs {
        run_cmd(
            "zpool",
            &["list", "-H", "-o", "name,health", &pool_name],
            &[],
        )
        .unwrap_or_default()
    } else {
        run_cmd(
            "findmnt",
            &["-rn", "-T", &mount_dir_str, "-o", "FSTYPE,OPTIONS"],
            &[],
        )
        .unwrap_or_default()
    };
    let queue_dir = mount_dir.join("queue");
    // The on-disk oplog lives next to the queue on the tested device: its
    // surviving prefix after a replay marks the durably completed ops.
    let disk_oplog = mount_dir.join("oplog.ndjson");
    let workload_status = std::process::Command::new(workload)
        .args([
            "--queue",
            queue_dir.to_str().ok_or("queue path not utf-8")?,
            "--oplog",
            oplog.to_str().ok_or("oplog path not utf-8")?,
            "--on-disk-oplog",
            disk_oplog.to_str().ok_or("oplog path not utf-8")?,
            "--seed",
            &a.seed.to_string(),
            "--ops",
            &a.ops.to_string(),
        ])
        .status()
        .map_err(|e| format!("spawn workload: {e}"))?;
    if !workload_status.success() {
        return Err(format!("workload failed: {workload_status}"));
    }
    if is_zfs {
        zpool_export_retry(&pool_name)?;
    } else {
        run_cmd("umount", &[&mount_dir_str], &[])?;
    }
    run_cmd("dmsetup", &["remove", &dm_name], &[])?;
    detach_loop(&loop_b);
    detach_loop(&loop_m);
    run.loops.clear();
    run.dm_names.clear();
    registry::upsert(&a.store, run)?;

    // 6. Enumerate persistence-barrier entries from the log.
    // xfstests replay-log: find mode walks entries from --start-entry and
    // prints "<entry>@<sector>" at the next flush/fua; replay mode applies
    // entries to --replay <target> with --limit N (entries 0..N-1).
    attach_loop_explicit(&loop_m, marker)?;
    guards::verify_block_target(&loop_m, marker, root)?;
    let replay_log = locate_replay_log();
    let mut barriers: Vec<u64> = Vec::new();
    for flag in ["--next-flush", "--next-fua"] {
        let mut start: u64 = 0;
        loop {
            let out = run_cmd(
                &replay_log,
                &[
                    "--log",
                    &loop_m,
                    "--find",
                    flag,
                    "--start-entry",
                    &start.to_string(),
                ],
                &[],
            );
            match out {
                Ok(line) => {
                    let Some(entry) = line.split('@').next().and_then(|n| n.parse::<u64>().ok())
                    else {
                        break;
                    };
                    barriers.push(entry);
                    start = entry + 1;
                }
                Err(_) => break, // no more barriers of this kind
            }
        }
    }
    barriers.sort_unstable();
    barriers.dedup();
    // The getopt table spells this option "num-entries"; the usage text
    // misleadingly prints "--number-entries".
    let nr_entries: u64 = run_cmd(&replay_log, &["--log", &loop_m, "--num-entries"], &[])?
        .trim()
        .parse()
        .unwrap_or(0);
    if barriers.is_empty() {
        detach_loop(&loop_m);
        return Err("no persistence barriers (flush/fua) found in log".into());
    }
    // Crash-equivalent states: the prefix including all data writes up to
    // each persistence barrier, plus the full log as the clean-completion
    // sanity state. Flush and FUA log entries carry no data, so the prefix
    // ending before a barrier is byte-identical to the previous state; only
    // the after-barrier prefixes are distinct.
    let mut limits: Vec<u64> = barriers
        .iter()
        .map(|b| (*b + 1).min(nr_entries.max(1)))
        .collect();
    if nr_entries > 0 {
        limits.push(nr_entries);
    }
    limits.sort_unstable();
    limits.dedup();

    // 7. Replay each prefix and check the crash state.
    let mut verdicts = Vec::new();
    let mut failures = Vec::new();
    for (i, limit) in limits.iter().enumerate() {
        if a.max_marks > 0 && i >= a.max_marks {
            break;
        }
        // Restore the pristine image: replaying onto the final-state image
        // would leave later writes in place and test an almost-final state
        // instead of the cut point.
        copy_sparse(&pristine, backing)?;
        // A fresh loop device per state: reusing a specific device races
        // the kernel's asynchronous release after umount (losetup -d
        // returns EBUSY until it completes). losetup --find picks any free
        // device; attachments that outlive a state are swept by teardown.
        let loop_state = attach_loop(backing)?;
        guards::verify_block_target(&loop_state, backing, root)?;
        run_cmd(
            &replay_log,
            &[
                "--log",
                &loop_m,
                "--replay",
                &loop_state,
                "--limit",
                &limit.to_string(),
            ],
            &[],
        )
        .map_err(|e| format!("replay limit {limit}: {e}"))?;

        let mount_result = if is_zfs {
            zfs_state_mount(&loop_state, &pool_name, mount_dir)
        } else {
            run_cmd("mount", &[&loop_state, &mount_dir.to_string_lossy()], &[]).map(|_| ())
        };
        let verdict_path = a.store.join(format!("{id}.e{limit}.verdict.json"));
        let pass = match mount_result {
            Ok(()) => {
                let status = std::process::Command::new(check)
                    .args([
                        "--queue",
                        queue_dir.to_str().ok_or("queue path not utf-8")?,
                        "--oplog",
                        disk_oplog.to_str().ok_or("oplog path not utf-8")?,
                        "--out",
                        verdict_path.to_str().ok_or("verdict path not utf-8")?,
                    ])
                    .status()
                    .map_err(|e| format!("spawn checker: {e}"))?;
                if is_zfs {
                    zpool_export_retry(&pool_name)?;
                } else {
                    umount_retry(mount_dir)?;
                }
                status.success()
            }
            // A crash state before pool creation: nothing durable exists.
            Err(e) if is_zfs && e.contains(POOL_ABSENT) => {
                write_json(&verdict_path, &json!({"pass": true, "pool_absent": true}))?;
                true
            }
            Err(e) => {
                // A crash state that cannot even mount is a catastrophic
                // durability failure for this profile.
                write_json(&verdict_path, &json!({"pass": false, "mount_error": e}))?;
                false
            }
        };
        verdicts.push(json!({"entries": limit, "pass": pass}));
        if !pass {
            failures.push(*limit);
        }
        umount_if_mounted(mount_dir);
        detach_loop_quiet(&loop_state);
        if !failures.is_empty() {
            // Keep everything for debugging the first failure.
            detach_loop(&loop_m);
            let manifest = json!({
                "id": id, "fs": a.fs, "ops": a.ops, "seed": a.seed,
                "kernel": kernel_version(), "mkfs": mkfs_version,
                "mount": mount_info, "barriers": barriers, "entries": nr_entries,
                "verdicts": verdicts, "failures": failures,
                "backing": backing.display().to_string(),
            });
            write_json(&a.store.join(format!("{id}.manifest.json")), &manifest)?;
            return Err(format!(
                "tier1: crash state at entry {limit} FAILED; images kept at {} / {}",
                backing.display(),
                marker.display()
            ));
        }
    }
    detach_loop(&loop_m);

    let manifest = json!({
        "id": id,
        "fs": a.fs,
        "tier": 1,
        "ops": a.ops,
        "seed": a.seed,
        "kernel": kernel_version(),
        "mkfs": mkfs_version,
        "mount": mount_info,
        "size_mb": a.size_mb,
        "entries": nr_entries,
        "barriers": barriers.len(),
        "states_checked": verdicts.len(),
        "verdicts": verdicts,
        "pass": failures.is_empty(),
        "started": now_iso(),
    });
    write_json(&a.store.join(format!("{id}.manifest.json")), &manifest)?;
    eprintln!(
        "tier1 {}: {} entries, {} barriers, {} states checked, all passed",
        a.fs,
        nr_entries,
        barriers.len(),
        verdicts.len()
    );
    Ok(())
}

pub(super) fn teardown_run_resources(run: &RegistryRun) {
    if let Some(pool) = &run.pool {
        let _ = std::process::Command::new("zpool")
            .args(["export", "-f", pool])
            .output();
    }
    if let Some(mount) = &run.mount {
        let _ = std::process::Command::new("umount").arg(mount).output();
    }
    for dm in &run.dm_names {
        let _ = std::process::Command::new("dmsetup")
            .args(["remove", dm])
            .output();
    }
    for loop_dev in &run.loops {
        let _ = std::process::Command::new("losetup")
            .args(["-d", loop_dev])
            .output();
    }
    // Loops re-attached after run.loops was cleared (log enumeration and
    // per-state replay re-attach by explicit device name) are not in the
    // registry list. Detach whatever is still attached to this run's own
    // images; losetup -j only reports loops backed by those files.
    for image in [run.backing.as_deref(), run.marker.as_deref()]
        .into_iter()
        .flatten()
    {
        detach_loops_for(Path::new(image));
    }
}

fn detach_loops_for(image: &Path) {
    let Ok(out) = std::process::Command::new("losetup")
        .arg("-j")
        .arg(image)
        .output()
    else {
        return;
    };
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let Some(dev) = line.split(':').next() else {
            continue;
        };
        if dev.trim_start_matches("/dev/").starts_with("loop") {
            let _ = std::process::Command::new("losetup")
                .args(["-d", dev])
                .output();
        }
    }
}

/// Copy a crash-lab image, skipping unwritten extents: the post-mkfs image
/// is mostly holes, so a sparse copy restores in time proportional to the
/// mkfs footprint rather than the image size.
fn copy_sparse(src: &Path, dst: &Path) -> Result<(), String> {
    let status = std::process::Command::new("cp")
        .args(["--sparse=always", "--reflink=auto"])
        .arg(src)
        .arg(dst)
        .status()
        .map_err(|e| format!("cp {src:?} -> {dst:?}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("cp {src:?} -> {dst:?} failed: {status}"))
    }
}

const POOL_ABSENT: &str = "crashlab-pool-absent";

/// Import the run's pool from exactly one device. Never issues a bare
/// `zpool import` (it scans every host device, including real pools);
/// the run's own loop device is the only device searched and only the
/// run's pool name is imported. Returns Err(POOL_ABSENT) when the replay
/// predates pool creation.
fn zfs_state_mount(dev: &str, pool: &str, _mount_dir: &Path) -> Result<(), String> {
    let listing = run_cmd("zpool", &["import", "-d", dev], &[])?;
    if !listing.contains(pool) {
        return Err(format!("{POOL_ABSENT}: {pool}"));
    }
    match run_cmd(
        "zpool",
        &["import", "-f", "-o", "cachefile=none", "-d", dev, pool],
        &[],
    ) {
        Ok(_) => Ok(()),
        // Labels are enumerable but no valid uberblock exists: ZFS
        // durability begins at uberblock commit, so nothing in this pool
        // was ever durable. Same vacuous class as pool-absent.
        Err(e) if e.contains("unavailable") || e.contains("corrupted data") => {
            Err(format!("{POOL_ABSENT}: import: {e}"))
        }
        Err(e) => Err(e),
    }
}

/// Export the run's pool, retrying while the checker's handles drain.
fn zpool_export_retry(pool: &str) -> Result<(), String> {
    for _ in 0..20 {
        let ok = std::process::Command::new("zpool")
            .args(["export", "-f", pool])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err(format!("zpool export {pool} still busy after retries"))
}

pub(super) fn allocate_image(path: &Path, size_mb: u64) -> Result<(), String> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .map_err(|e| format!("create image {}: {e}", path.display()))?;
    file.set_len(size_mb * 1024 * 1024)
        .map_err(|e| format!("fallocate {}: {e}", path.display()))?;
    file.sync_all().map_err(|e| format!("sync image: {e}"))?;
    Ok(())
}

pub(super) fn attach_loop(backing: &Path) -> Result<String, String> {
    let out = run_cmd(
        "losetup",
        &["--find", "--show", "--direct-io=on"],
        &[&backing.display().to_string()],
    )?;
    let dev = out.trim().to_string();
    if dev.starts_with("/dev/loop") {
        Ok(dev)
    } else {
        Err(format!("losetup returned unexpected output: {out}"))
    }
}

/// Attach a loop device, retrying: after a successful detach the kernel can
/// still take a moment to free the device, so an immediate attach can fail
/// with EBUSY.
fn attach_loop_explicit(dev: &str, backing: &Path) -> Result<(), String> {
    let mut last_err = String::new();
    for _attempt in 0..20 {
        match run_cmd(
            "losetup",
            &["--direct-io=on", dev, &backing.display().to_string()],
            &[],
        ) {
            Ok(_) => return Ok(()),
            Err(e) => {
                last_err = e;
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }
    Err(format!(
        "attach {dev} to {} failed after retries: {last_err}",
        backing.display()
    ))
}

/// Detach a loop device, retrying: the kernel releases the loop reference
/// asynchronously after umount, so an immediate detach can fail with EBUSY.
pub(super) fn detach_loop(dev: &str) {
    for attempt in 0..20 {
        let ok = std::process::Command::new("losetup")
            .args(["-d", dev])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
        if attempt == 19 {
            eprintln!("crashlab: warning: could not detach {dev} after retries");
        }
    }
}

/// Detach a per-state loop device, briefly and silently: the kernel's
/// asynchronous release can make this fail EBUSY, which is expected and
/// harmless because teardown detaches every loop backed by the run's images.
fn detach_loop_quiet(dev: &str) {
    for _ in 0..5 {
        let ok = std::process::Command::new("losetup")
            .args(["-d", dev])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// Unmount without failing the caller: used on paths where the state's
/// verdict has already been decided and a leftover mount is cleaned by
/// teardown.
pub(super) fn umount_if_mounted(mount_dir: &Path) {
    let target = mount_dir.to_string_lossy();
    let _ = std::process::Command::new("umount").arg(&*target).output();
}

/// Unmount, retrying briefly: a just-exited checker's file handles can take
/// a moment to release. Returns Err when the mount is still busy so callers
/// fail the state loudly instead of corrupting the next one.
pub(super) fn umount_retry(mount_dir: &Path) -> Result<(), String> {
    let target = mount_dir.to_string_lossy();
    for _attempt in 0..20 {
        let ok = std::process::Command::new("umount")
            .arg(&*target)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err(format!("umount {target} still busy after retries"))
}

pub(super) fn sectors_of(dev: &str) -> Result<String, String> {
    let out = run_cmd("blockdev", &["--getsz", dev], &[])?;
    let n: u64 = out
        .trim()
        .parse()
        .map_err(|_| format!("bad blockdev --getsz output: {out}"))?;
    Ok(n.to_string())
}

pub(super) fn kernel_version() -> String {
    std::process::Command::new("uname")
        .arg("-r")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

pub(super) fn is_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim()
                .parse::<u32>()
                .ok()
        })
        == Some(0)
}

fn preflight(fs: &str) -> Result<(), String> {
    for tool in [
        "losetup", "dmsetup", "mount", "umount", "blockdev", "findmnt",
    ] {
        if which(tool).is_none() {
            return Err(format!("missing tool: {tool}"));
        }
    }
    if !Path::new(&locate_replay_log()).is_file() && which("replay-log").is_none() {
        return Err(
            "missing tool: replay-log (build from xfstests log-writes, install to ~/.local/bin)"
                .into(),
        );
    }
    if fs == "zfs" {
        for tool in ["zpool", "zfs"] {
            if which(tool).is_none() {
                return Err(format!("missing tool: {tool}"));
            }
        }
    } else if which(&format!("mkfs.{fs}")).is_none() {
        return Err(format!("missing mkfs.{fs}"));
    }
    Ok(())
}

fn print_preflight_device_map() {
    if let Ok(out) = std::process::Command::new("lsblk")
        .args(["-o", "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS,MODEL"])
        .output()
    {
        eprintln!("--- device map (guards active) ---");
        eprintln!(
            "{}",
            guards::annotate_lsblk(&String::from_utf8_lossy(&out.stdout))
        );
        eprintln!("----------------------------------");
    }
}

fn which(tool: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(tool))
        .find(|candidate| candidate.is_file())
}

/// replay-log may live outside root's PATH (user-local install).
fn locate_replay_log() -> String {
    if which("replay-log").is_some() {
        return "replay-log".into();
    }
    for candidate in [
        std::env::var("HOME")
            .ok()
            .map(|h| format!("{h}/.local/bin/replay-log")),
        Some("/dev/shm/crashlab/replay-log".into()),
        Some("/usr/local/bin/replay-log".into()),
    ]
    .into_iter()
    .flatten()
    {
        if Path::new(&candidate).is_file() {
            return candidate;
        }
    }
    "replay-log".into()
}
