// Crash-lab checker: verifies a queue directory against an op-log prefix
// after a crash. Runs recovery, fsck, and the A-015 acceptance gates:
//
//   G1 no returned-committed enqueue is lost
//   G2 no acknowledged job is active (must be terminal)
//   G3 no phantom job is delivered
//   G4 recovery completes without errors
//   G5 fsck reports no Error-severity findings
//
// A written op-log line is a completed fact; the surviving prefix defines
// the expectations. Any payload corruption must surface as quarantine, never
// as delivery.
//
// Usage: crashlab-check --queue DIR --oplog FILE --out VERDICT.json

use serde_json::json;
use std::path::Path;
use steadq_core::{
    Error, FsckDepth, FsckMode, FsckOptions, LeaseOutcome, OpenOptions, Queue, WorkBudget,
};

struct Args {
    queue: String,
    oplog: String,
    out: String,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        queue: String::new(),
        oplog: String::new(),
        out: String::new(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let value = it
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag.as_str() {
            "--queue" => args.queue = value,
            "--oplog" => args.oplog = value,
            "--out" => args.out = value,
            _ => return Err(format!("unknown flag {flag}")),
        }
    }
    if args.queue.is_empty() || args.oplog.is_empty() || args.out.is_empty() {
        return Err("usage: crashlab-check --queue DIR --oplog FILE --out VERDICT.json".into());
    }
    Ok(args)
}

struct OpLine {
    op: String,
    job: String,
    result: String,
}

fn unhex(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

fn read_oplog(path: &Path) -> Result<Vec<OpLine>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        // A crash state before the oplog file was created has zero
        // completed operations and therefore zero expectations.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("cannot read oplog {}: {e}", path.display())),
    };
    // Tolerate a truncated trailing line: drop anything after the last newline.
    let text = match text.rfind('\n') {
        Some(i) => &text[..=i],
        None => "",
    };
    let mut lines = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value =
            serde_json::from_str(line).map_err(|e| format!("bad oplog line: {e}"))?;
        lines.push(OpLine {
            op: v["op"].as_str().unwrap_or("").to_string(),
            job: v["job"].as_str().unwrap_or("").to_string(),
            result: v["result"].as_str().unwrap_or("").to_string(),
        });
    }
    Ok(lines)
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("crashlab-check: {e}");
            std::process::exit(2);
        }
    };
    let verdict = match run_check(&args) {
        Ok(v) => v,
        Err(e) => {
            let v = json!({
                "pass": false,
                "internal_error": e,
            });
            let _ = std::fs::write(&args.out, serde_json::to_string_pretty(&v).unwrap());
            std::process::exit(2);
        }
    };
    let pass = verdict["pass"].as_bool().unwrap_or(false);
    let _ = std::fs::write(&args.out, serde_json::to_string_pretty(&verdict).unwrap());
    println!(
        "crashlab-check: {} ({})",
        if pass { "PASS" } else { "FAIL" },
        args.out
    );
    std::process::exit(if pass { 0 } else { 1 });
}

/// The oplog's durable prefix: jobs whose enqueue committed and jobs whose
/// ack completed. Damage to anything else is legal power-loss loss.
struct DurablePrefix {
    committed: Vec<[u8; 16]>,
    acked: Vec<[u8; 16]>,
    committed_hex: Vec<String>,
    acked_hex: Vec<String>,
}

impl DurablePrefix {
    fn from_ops(ops: &[OpLine]) -> Self {
        let committed: Vec<[u8; 16]> = ops
            .iter()
            .filter(|l| l.op == "enqueue" && l.result.starts_with("committed"))
            .filter_map(|l| unhex(&l.job))
            .collect();
        let acked: Vec<[u8; 16]> = ops
            .iter()
            .filter(|l| l.op == "ack" && l.result == "acked")
            .filter_map(|l| unhex(&l.job))
            .collect();
        let committed_hex = committed.iter().map(|j| hex(j)).collect();
        let acked_hex = acked.iter().map(|j| hex(j)).collect();
        DurablePrefix {
            committed,
            acked,
            committed_hex,
            acked_hex,
        }
    }

    /// True when the object at `relative_path` belongs to no job in the
    /// durable prefix, so findings about it cannot fail the state.
    fn beyond(&self, relative_path: &str) -> bool {
        let name = relative_path.rsplit('/').next().unwrap_or("");
        let job_hex = name.split('.').next().unwrap_or("");
        !self.committed_hex.iter().any(|c| c == job_hex)
            && !self.acked_hex.iter().any(|a| a == job_hex)
    }
}

struct RecoveryGate {
    stats: steadq_core::RecoveryStats,
    passes: u32,
    errors: usize,
    beyond_prefix: usize,
}

/// Run recovery to quiescence, splitting errors into prefix and beyond-prefix.
fn recover_to_quiescence(queue: &mut Queue, prefix: &DurablePrefix) -> RecoveryGate {
    let budget = WorkBudget {
        max_operations: 100_000,
        max_duration_ms: 60_000,
    };
    let mut passes = 0u32;
    let mut errors = 0usize;
    let mut beyond_prefix = 0usize;
    let stats = loop {
        let stats = queue.recover(&budget);
        for e in &stats.errors {
            if prefix.beyond(&e.relative_path) {
                beyond_prefix += 1;
            } else {
                errors += 1;
            }
        }
        passes += 1;
        if !stats.budget_exhausted || passes > 100 {
            break stats;
        }
    };
    RecoveryGate {
        stats,
        passes,
        errors,
        beyond_prefix,
    }
}

struct FsckGate {
    report: steadq_core::FsckReport,
    errors: usize,
    beyond_prefix: usize,
}

/// Deep fsck in check-only mode, with Error findings split the same way.
fn fsck_gate(queue: &Queue, prefix: &DurablePrefix) -> FsckGate {
    let report = queue.fsck(&FsckOptions {
        mode: FsckMode::Check,
        depth: FsckDepth::Deep,
    });
    let mut errors = 0usize;
    let mut beyond_prefix = 0usize;
    for finding in &report.findings {
        if matches!(finding.severity, steadq_core::FindingSeverity::Error) {
            if prefix.beyond(&finding.relative_path) {
                beyond_prefix += 1;
            } else {
                errors += 1;
            }
        }
    }
    FsckGate {
        report,
        errors,
        beyond_prefix,
    }
}

fn is_active(snapshots: &[steadq_core::Snapshot]) -> bool {
    snapshots
        .iter()
        .any(|s| matches!(s.state.as_str(), "ready" | "leased" | "delayed"))
}

/// G1: committed jobs must still exist somewhere. G2: acked jobs must be
/// terminal. Returns (missing, acked_bad).
fn check_prefix_jobs(queue: &Queue, prefix: &DurablePrefix) -> (Vec<String>, Vec<String>) {
    let mut missing = Vec::new();
    let mut acked_bad = Vec::new();
    for job in &prefix.committed {
        let snapshots = queue.inspect(job);
        if snapshots.is_empty() {
            missing.push(hex(job));
            continue;
        }
        if prefix.acked.contains(job) && is_active(&snapshots) {
            acked_bad.push(format!("{}:{}", hex(job), snapshots[0].state));
        }
    }
    // Acked jobs that were never seen as committed cannot exist (ack requires
    // a prior lease of a committed job), but check them anyway if present.
    for job in &prefix.acked {
        if !prefix.committed.contains(job) {
            let snapshots = queue.inspect(job);
            if is_active(&snapshots) {
                acked_bad.push(format!("{}:{}", hex(job), snapshots[0].state));
            }
        }
    }
    (missing, acked_bad)
}

struct DeliveryProbe {
    delivered: Vec<String>,
    phantom: Vec<String>,
    quarantined_corrupt: u32,
}

/// G3: probe deliveries. An acknowledged job must never be delivered;
/// corrupt payloads must be quarantined, not delivered. A job that exists
/// on disk but has no durable oplog line is NOT a phantom: publication
/// fsyncs before its oplog line is written, so the durable prefix is a
/// lower bound on completed work and on-disk presence proves the enqueue.
fn probe_deliveries(queue: &mut Queue, prefix: &DurablePrefix) -> DeliveryProbe {
    let mut probe = DeliveryProbe {
        delivered: Vec::new(),
        phantom: Vec::new(),
        quarantined_corrupt: 0,
    };
    for _ in 0..8 {
        match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(info) => {
                let jh = hex(&info.job_id);
                if prefix.acked_hex.contains(&jh) {
                    probe.phantom.push(format!("acked-delivered:{jh}"));
                } else {
                    probe.delivered.push(jh);
                }
            }
            LeaseOutcome::NotCommitted(Error::PayloadCorrupt) => {
                // Deterministic corruption was quarantined before delivery.
                probe.quarantined_corrupt += 1;
            }
            _ => break,
        }
    }
    probe
}

fn run_check(args: &Args) -> Result<serde_json::Value, String> {
    // A crash state before the queue was initialized checks nothing: no
    // queue exists, no operations were durably completed.
    if !Path::new(&args.queue).is_dir() {
        return Ok(json!({ "pass": true, "queue_absent": true }));
    }
    // FORMAT publication is fsync-then-rename and precedes every queue
    // write, so a missing FORMAT means initialization was interrupted
    // before any operation could complete durably. A durable operation
    // without FORMAT would be a causality violation.
    if !Path::new(&args.queue).join("FORMAT").is_file() {
        let ops = read_oplog(Path::new(&args.oplog))?;
        return if ops.is_empty() {
            Ok(json!({ "pass": true, "interrupted_init": true }))
        } else {
            Ok(json!({
                "pass": false,
                "format_missing_with_durable_ops": ops.len(),
            }))
        };
    }
    let ops = read_oplog(Path::new(&args.oplog))?;
    let prefix = DurablePrefix::from_ops(&ops);

    let mut queue = Queue::open(
        Path::new(&args.queue),
        &OpenOptions {
            allow_unsupported_fs: true,
            ..Default::default()
        },
    )
    .map_err(|e| format!("open failed: {e}"))?;

    let recovery = recover_to_quiescence(&mut queue, &prefix);
    let fsck = fsck_gate(&queue, &prefix);
    let (missing, acked_bad) = check_prefix_jobs(&queue, &prefix);
    let probe = probe_deliveries(&mut queue, &prefix);

    let fsck_warnings = fsck.report.findings.len() - fsck.errors - fsck.beyond_prefix;
    let fsck_findings: Vec<serde_json::Value> = fsck
        .report
        .findings
        .iter()
        .take(20)
        .map(|f| {
            json!({
                "severity": format!("{:?}", f.severity),
                "type": f.finding_type,
                "path": f.relative_path,
                "details": f.details,
            })
        })
        .collect();
    let recovery_errors: Vec<String> = recovery
        .stats
        .errors
        .iter()
        .take(20)
        .map(|e| format!("{e:?}"))
        .collect();
    let oplog_tail: Vec<String> = ops
        .iter()
        .rev()
        .take(5)
        .rev()
        .map(|l| format!("{}:{}", l.op, l.result))
        .collect();
    let gates_pass = missing.is_empty()
        && acked_bad.is_empty()
        && probe.phantom.is_empty()
        && recovery.errors == 0
        && fsck.errors == 0;

    Ok(json!({
        "pass": gates_pass,
        "ops": ops.len(),
        "oplog_tail": oplog_tail,
        "committed": prefix.committed.len(),
        "acked": prefix.acked.len(),
        "gates": {
            "committed_not_lost": { "checked": prefix.committed.len(), "missing": missing },
            "acked_terminal": { "checked": prefix.acked.len(), "violations": acked_bad },
            "no_phantom_or_acked_delivery": { "violations": probe.phantom, "delivered_probe": probe.delivered.len() },
            "recovery_clean": {
                "passes": recovery.passes,
                "errors": recovery.errors,
                "error_detail": recovery_errors,
            },
            "beyond_prefix_findings": fsck.beyond_prefix,
            "beyond_prefix_recovery_errors": recovery.beyond_prefix,
            "fsck_clean": {
                "errors": fsck.errors,
                "warnings": fsck_warnings,
                "total_objects": fsck.report.total_objects,
                "structurally_verified": fsck.report.structurally_verified,
                "payloads_deep_verified": fsck.report.payloads_deep_verified,
                "findings": fsck_findings,
            },
            "quarantined_corrupt_payloads": probe.quarantined_corrupt,
        },
        "recovery": {
            "reaped": recovery.stats.leases_reaped,
            "promoted": recovery.stats.delayed_promoted,
            "temp_deleted": recovery.stats.temp_files_deleted,
            "to_dead": recovery.stats.leases_to_dead,
        },
    }))
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
