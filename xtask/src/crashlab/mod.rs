// Crash lab (A-015): device-safe storage crash certification tooling.
//
// Subcommands live in tier0/tier1; guards enforce the device-safety contract
// (never the OS drive, never data devices, only loop devices this tooling
// created over allowlisted image stores); registry tracks resources for
// teardown after interrupted runs.

pub mod flakey;
pub mod guards;
pub mod registry;
pub mod tier0;
pub mod tier1;

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_iso() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Days-to-civil algorithm; good enough for evidence timestamps (UTC).
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mth <= 2 { y + 1 } else { y };
    format!("{y:04}-{mth:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

pub fn write_json(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    std::fs::write(
        path,
        serde_json::to_string_pretty(value).map_err(|e| format!("serialize: {e}"))?,
    )
    .map_err(|e| format!("write {}: {e}", path.display()))
}

/// Build (if needed) and return the two crash-lab binaries. Skips the build
/// when both already exist so the orchestrator can run under sudo without
/// root-owned build artifacts.
pub fn ensure_bins(root: &Path) -> Result<(PathBuf, PathBuf), String> {
    let dir = root.join("target/debug");
    let workload = dir.join("crashlab-workload");
    let check = dir.join("crashlab-check");
    if workload.is_file() && check.is_file() {
        return Ok((workload, check));
    }
    let status = std::process::Command::new(cargo_bin())
        .args(["build", "-p", "steadq-testkit", "--bins"])
        .current_dir(root)
        .status()
        .map_err(|e| format!("cargo build: {e}"))?;
    if !status.success() {
        return Err("cargo build -p steadq-testkit --bins failed".into());
    }
    Ok((workload, check))
}

fn cargo_bin() -> String {
    std::env::var("CARGO").unwrap_or_else(|_| "cargo".into())
}

pub fn run_cmd(program: &str, fixed: &[&str], trailing: &[&String]) -> Result<String, String> {
    let mut cmd = std::process::Command::new(program);
    cmd.args(fixed);
    for t in trailing {
        cmd.arg(t);
    }
    let output = cmd
        .output()
        .map_err(|e| format!("{program} failed to start: {e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !output.status.success() {
        return Err(format!(
            "{program} {:?} failed ({}): {}",
            fixed,
            output.status,
            if stderr.is_empty() { &stdout } else { &stderr }
        ));
    }
    Ok(if stdout.is_empty() { stderr } else { stdout })
}

pub fn dispatch(root: &Path, sub: &str, args: &[String]) -> Result<(), String> {
    match sub {
        "doctor" => doctor(root),
        "tier0" => tier0::run(root, args),
        "tier1" => tier1::run(root, args),
        "flakey" => flakey::run(root, args),
        "teardown" => {
            let store = args
                .first()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/dev/shm/crashlab"));
            let torn = registry::teardown_active(&store)?;
            eprintln!(
                "crashlab teardown: {torn} runs cleaned up at {}",
                store.display()
            );
            Ok(())
        }
        "help" | "-h" | "--help" => {
            eprintln!(
                "usage: cargo xtask crashlab <doctor|tier0|tier1|flakey|teardown> [args]\n\
                 \n\
                 tier0 [--runs N] [--ops N] [--seed N] [--store DIR]  SIGKILL lane, no root\n\
                 tier1 --fs ext4|xfs|btrfs|f2fs [--ops N] [--seed N] [--size-mb N]\n\
                       [--store DIR] [--max-marks N] [--keep-images]   dm-log-writes replay, root\n\
                 flakey [--cuts N] [--seed N] [--workers N] [--mode drop_writes|error_writes]\n\
                       [--mount-opts OPTS] [--min-ops N] [--max-ops N] [--size-mb N]\n\
                       [--store DIR]                     dm-flakey power cuts on ext4, root\n\
                 teardown [STORE]                                       recover a crashed run\n\
                 \n\
                 Safety: only loop devices over images in allowlisted stores\n\
                 (/dev/shm/crashlab, target/crashlab, $CRASHLAB_STORE)\n\
                 are ever touched. The OS drive and data devices are refused."
            );
            Ok(())
        }
        _ => Err(format!("unknown crashlab subcommand: {sub}")),
    }
}

fn doctor(root: &Path) -> Result<(), String> {
    eprintln!("crashlab doctor");
    eprintln!("  kernel: {}", tier1_kernel());
    eprintln!(
        "  root: {}",
        if is_root() {
            "yes"
        } else {
            "no (tier1 needs sudo)"
        }
    );
    eprintln!("  allowed stores:");
    for store in guards::allowed_stores(root) {
        let exists = store.exists();
        eprintln!(
            "    {} {}",
            store.display(),
            if exists {
                "(exists)"
            } else {
                "(create on first use)"
            }
        );
    }
    eprintln!("  tools:");
    for tool in [
        "losetup",
        "dmsetup",
        "mount",
        "umount",
        "blockdev",
        "findmnt",
        "replay-log",
        "mkfs.ext4",
        "mkfs.xfs",
        "mkfs.btrfs",
        "mkfs.f2fs",
        "zpool",
        "zfs",
    ] {
        let note = match which(tool) {
            Some(_) => String::new(),
            None => {
                if tool == "replay-log" {
                    " MISSING (build from xfstests log-writes)".to_string()
                } else if tool == "mkfs.f2fs" {
                    " MISSING (apt install f2fs-tools)".to_string()
                } else {
                    " MISSING".to_string()
                }
            }
        };
        eprintln!("    {tool}{note}");
    }
    eprintln!(
        "  dm modules: dm-log-writes {}, dm-flakey {}",
        if module_loaded("dm_log_writes") {
            "loaded"
        } else {
            "available/autoload"
        },
        if module_loaded("dm_flakey") {
            "loaded"
        } else {
            "available/autoload"
        },
    );
    if let Ok(out) = std::process::Command::new("lsblk")
        .args(["-o", "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS,MODEL"])
        .output()
    {
        eprintln!("  device map:");
        eprintln!(
            "{}",
            guards::annotate_lsblk(&String::from_utf8_lossy(&out.stdout))
        );
    }
    eprintln!("  guard self-test: run `cargo test -p xtask`");
    Ok(())
}

fn tier1_kernel() -> String {
    std::process::Command::new("uname")
        .arg("-r")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

fn is_root() -> bool {
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

fn module_loaded(name: &str) -> bool {
    std::fs::read_to_string("/proc/modules")
        .map(|text| text.lines().any(|l| l.starts_with(name)))
        .unwrap_or(false)
}

fn which(tool: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(tool))
        .find(|candidate| candidate.is_file())
}
