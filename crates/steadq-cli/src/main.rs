// SteadQ command-line interface.

use std::os::unix::io::AsFd;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// Stable exit codes (spec: exit-code table)
const EXIT_SUCCESS: u8 = 0;
const EXIT_ORDINARY: u8 = 1;
const EXIT_INDETERMINATE: u8 = 2;
const EXIT_CORRUPTION: u8 = 3;
const EXIT_RESOURCE_EXHAUSTED: u8 = 4;
const EXIT_PERMISSION: u8 = 5;
const EXIT_IO_FAILURE: u8 = 6;
const EXIT_UNSUPPORTED: u8 = 64;
use steadq_core::{
    CreateOptions, EnqueueInput, EnqueueOutcome, Error, FindingSeverity, FsckDepth, FsckMode,
    FsckOptions, LeaseOutcome, OpenOptions, Queue,
};

fn exit(code: u8) -> ExitCode {
    ExitCode::from(code)
}

/// Map a core error to its stable CLI exit code.
pub(crate) fn core_exit_code(error: &Error) -> u8 {
    match error {
        Error::QueueCorrupt(_) | Error::PayloadCorrupt | Error::QueuePoisoned(_) => EXIT_CORRUPTION,
        Error::UnsupportedFilesystem | Error::UnsupportedFormat => EXIT_UNSUPPORTED,
        Error::PermissionDenied => EXIT_PERMISSION,
        Error::ResourceExhausted | Error::StateExhausted => EXIT_RESOURCE_EXHAUSTED,
        Error::IoFailure(_) | Error::InvalidClock => EXIT_IO_FAILURE,
        Error::InvalidInput(_)
        | Error::InvalidTicket(_)
        | Error::NotCommitted(_)
        | Error::MaintenanceBusy
        | Error::IdentityCollision => EXIT_ORDINARY,
    }
}

fn exit_core(error: &Error) -> ExitCode {
    exit(core_exit_code(error))
}

fn exit_io(error: &std::io::Error) -> ExitCode {
    exit(match error.kind() {
        std::io::ErrorKind::Unsupported => EXIT_UNSUPPORTED,
        std::io::ErrorKind::PermissionDenied => EXIT_PERMISSION,
        std::io::ErrorKind::StorageFull | std::io::ErrorKind::QuotaExceeded => {
            EXIT_RESOURCE_EXHAUSTED
        }
        std::io::ErrorKind::AlreadyExists
        | std::io::ErrorKind::InvalidInput
        | std::io::ErrorKind::InvalidData
        | std::io::ErrorKind::WouldBlock => EXIT_ORDINARY,
        _ => EXIT_IO_FAILURE,
    })
}

/// Open the queue or print the failure and hand back the spec exit code.
fn open_or_exit(path: &std::path::Path) -> Result<Queue, ExitCode> {
    Queue::open(path, &OpenOptions::default()).map_err(|e| {
        eprintln!("open failed: {e}");
        exit_core(&e)
    })
}

/// Parse a 32-digit lowercase hex identifier or exit 1 naming the field.
fn parse_hex_id(value: &str, label: &str) -> Result<[u8; 16], ExitCode> {
    steadq_names::hex_decode_16(value).ok_or_else(|| {
        eprintln!("invalid {label}");
        exit(EXIT_ORDINARY)
    })
}

#[derive(Parser)]
#[command(name = "steadq", about = "Crash-safe filesystem queue")]
struct Cli {
    /// Emit JSON (honored by stats and doctor only)
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new queue
    Init {
        path: PathBuf,
        #[arg(long, default_value = "64")]
        shards: u32,
        #[arg(long, default_value = "3600000000000")]
        terminal_bucket_width_ns: u64,
    },
    /// Enqueue a job
    Put {
        path: PathBuf,
        /// Input file, or - for stdin
        file: Option<String>,
        #[arg(long, default_value = "application/octet-stream")]
        content_type: String,
        #[arg(long, default_value = "3")]
        max_attempts: u32,
        #[arg(long)]
        not_before: Option<u64>,
        #[arg(long)]
        producer_id: Option<String>,
    },
    /// Lease a job. Without --handle-file the handle JSON goes to stdout
    /// (save it and pass it as --handle-file) and the summary to stderr
    Lease {
        path: PathBuf,
        #[arg(long, default_value = "30")]
        duration_seconds: u64,
        #[arg(long)]
        handle_file: Option<PathBuf>,
        /// Write the transition ticket here on an indeterminate outcome
        #[arg(long)]
        ticket_out: Option<PathBuf>,
    },
    /// Per-state object counts and oldest-object age
    Stats {
        path: PathBuf,
        /// Emit Prometheus textfile format instead of plain lines
        #[arg(long)]
        prometheus: bool,
    },
    /// Doctor: check environment
    Doctor { path: PathBuf },
    /// Check queue integrity: name tags, digests, shard placement
    Fsck {
        path: PathBuf,
        /// Also hash and verify payload digests
        #[arg(long)]
        deep: bool,
        /// Quarantine corrupt objects instead of only reporting
        #[arg(long)]
        repair: bool,
    },
    /// Acknowledge a lease
    Ack {
        path: PathBuf,
        #[arg(long)]
        handle_file: PathBuf,
        /// Write the transition ticket here on an indeterminate outcome
        #[arg(long)]
        ticket_out: Option<PathBuf>,
    },
    /// Retry a lease
    Retry {
        path: PathBuf,
        #[arg(long)]
        handle_file: PathBuf,
        #[arg(long)]
        after_seconds: Option<u64>,
        /// Write the transition ticket here on an indeterminate outcome
        #[arg(long)]
        ticket_out: Option<PathBuf>,
    },
    /// Bury a lease
    Bury {
        path: PathBuf,
        #[arg(long)]
        handle_file: PathBuf,
        /// Dead reason: 0-4 or unspecified, consumer_rejected,
        /// unsupported_content_type, administrative_bury, attempts_exhausted
        #[arg(long, default_value = "0")]
        reason: String,
        /// Write the transition ticket here on an indeterminate outcome
        #[arg(long)]
        ticket_out: Option<PathBuf>,
    },
    /// Run a command for each leased job: payload on stdin, lease renewed
    /// while it runs, ack on exit 0, requeue on nonzero.
    ///
    /// The child sees STEADQ_JOB_ID (32 hex digits) and STEADQ_ATTEMPT in
    /// its environment and is killed if the worker dies. The command is
    /// checked on PATH before any lease; a missing command exits 127. If
    /// spawning fails later, that job is requeued (one attempt consumed)
    /// and the worker exits 127. SIGTERM or SIGINT stops leasing, forwards
    /// SIGTERM to running children, and exits 0 once they finish; a second
    /// signal exits at once. With --once the exit code is the child's own
    /// code (128+N if it died from signal N), which can overlap steadq's
    /// own exit codes.
    Work {
        path: PathBuf,
        /// Worker threads, each with its own queue handle
        #[arg(long, default_value = "1", value_parser = clap::value_parser!(u32).range(1..))]
        concurrency: u32,
        /// Lease duration; renewed at half this interval, and every
        /// min(duration/8, 1s) after a failed renewal
        #[arg(long, default_value = "60")]
        lease_seconds: u64,
        /// Run one job, then exit with the job's exit code
        #[arg(long)]
        once: bool,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },
    /// Run a recovery pass
    Recover {
        path: PathBuf,
        #[arg(long)]
        watch: bool,
        #[arg(long, default_value = "1000")]
        budget_ops: u32,
        #[arg(long, default_value = "100")]
        budget_ms: u64,
    },
    /// Inspect a job by ID
    Inspect { path: PathBuf, job_id: String },
    /// Verify a job or receipt file
    Verify {
        file: PathBuf,
        #[arg(long)]
        deep: bool,
    },
    /// Dump format info for a file
    FormatDump { file: PathBuf },
    /// Resolve an indeterminate operation
    Resolve {
        path: PathBuf,
        #[arg(long)]
        result_file: PathBuf,
        #[arg(long)]
        stabilize: bool,
    },
    /// Run a benchmark. Leases and acks whatever is in the queue, so it
    /// refuses a queue holding ready, leased, or delayed jobs
    Bench {
        path: PathBuf,
        /// Run even if the queue holds jobs; they will be consumed
        #[arg(long)]
        allow_nonempty: bool,
        #[arg(long, default_value = "1")]
        producers: u32,
        #[arg(long, default_value = "1")]
        consumers: u32,
        #[arg(long, default_value = "10")]
        duration_seconds: u64,
        #[arg(long, default_value = "1024")]
        payload_size: usize,
        #[arg(long, default_value = "30")]
        lease_duration_seconds: u64,
    },
    /// Administrative operations
    Admin {
        #[command(subcommand)]
        command: AdminCommands,
    },
}

#[derive(Subcommand)]
enum AdminCommands {
    /// List dead jobs
    DeadList { path: PathBuf },
    /// Inspect a dead job
    DeadInspect { path: PathBuf, job_id: String },
    /// Export a dead job's payload
    DeadExport {
        path: PathBuf,
        job_id: String,
        output: PathBuf,
    },
    /// Remove a dead job
    DeadRemove { path: PathBuf, job_id: String },
    /// List quarantined objects
    QuarantineList { path: PathBuf },
    /// Inspect a quarantined object
    QuarantineInspect {
        path: PathBuf,
        quarantine_id: String,
    },
    /// Export a quarantined object's raw bytes
    QuarantineExport {
        path: PathBuf,
        quarantine_id: String,
        output: PathBuf,
    },
    /// Remove a quarantined object
    QuarantineRemove {
        path: PathBuf,
        quarantine_id: String,
    },
    /// Run full recovery passes (reap, promote, compact and expire
    /// receipts) until one completes within budget
    CompactReceipts { path: PathBuf },
}

fn parse_duration_seconds(s: u64) -> Option<u64> {
    s.checked_mul(1_000_000_000)
}

fn doctor_filesystem(magic: i64) -> (&'static str, bool) {
    if let Some(name) = steadq_fs_linux::supported_filesystem_name(magic) {
        return (name, true);
    }
    match magic {
        steadq_fs_linux::TMPFS_MAGIC => ("tmpfs_not_certified", false),
        steadq_fs_linux::NFS_SUPER_MAGIC => ("nfs_refused", false),
        steadq_fs_linux::FUSE_SUPER_MAGIC => ("fuse_refused", false),
        steadq_fs_linux::OVERLAYFS_SUPER_MAGIC => ("overlay_refused", false),
        _ => ("unknown_refused", false),
    }
}

mod work;

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init {
            path,
            shards,
            terminal_bucket_width_ns,
        } => cmd_init(path, shards, terminal_bucket_width_ns),

        Commands::Put {
            path,
            file,
            content_type,
            max_attempts,
            not_before,
            producer_id,
        } => cmd_put(
            path,
            file,
            content_type,
            max_attempts,
            not_before,
            producer_id,
        ),

        Commands::Lease {
            path,
            duration_seconds,
            handle_file,
            ticket_out,
        } => cmd_lease(path, duration_seconds, handle_file, ticket_out),

        Commands::Stats { path, prometheus } => cmd_stats(path, prometheus, cli.json),

        Commands::Fsck { path, deep, repair } => cmd_fsck(path, deep, repair),

        Commands::Doctor { path } => cmd_doctor(path, cli.json),

        Commands::Ack {
            path,
            handle_file,
            ticket_out,
        } => cmd_ack(path, handle_file, ticket_out),

        Commands::Retry {
            path,
            handle_file,
            after_seconds,
            ticket_out,
        } => cmd_retry(path, handle_file, after_seconds, ticket_out),

        Commands::Bury {
            path,
            handle_file,
            reason,
            ticket_out,
        } => cmd_bury(path, handle_file, reason, ticket_out),

        Commands::Inspect { path, job_id } => cmd_inspect(path, job_id),

        Commands::Verify { file, deep } => cmd_verify(file, deep),

        Commands::FormatDump { file } => cmd_format_dump(file),

        Commands::Work {
            path,
            concurrency,
            lease_seconds,
            once,
            command,
        } => cmd_work(path, concurrency, lease_seconds, once, command),

        Commands::Recover {
            path,
            watch,
            budget_ops,
            budget_ms,
        } => cmd_recover(path, watch, budget_ops, budget_ms),
        Commands::Resolve {
            path,
            result_file,
            stabilize,
        } => cmd_resolve(path, result_file, stabilize),

        Commands::Bench {
            path,
            allow_nonempty,
            producers,
            consumers,
            duration_seconds,
            payload_size,
            lease_duration_seconds,
        } => cmd_bench(
            path,
            allow_nonempty,
            producers,
            consumers,
            duration_seconds,
            payload_size,
            lease_duration_seconds,
        ),

        Commands::Admin { command } => match command {
            AdminCommands::DeadList { path } => cmd_dead_list(path),
            AdminCommands::DeadInspect { path, job_id } => cmd_dead_inspect(path, job_id),
            AdminCommands::DeadExport {
                path,
                job_id,
                output,
            } => cmd_dead_export(path, job_id, output),
            AdminCommands::DeadRemove { path, job_id } => cmd_dead_remove(path, job_id),
            AdminCommands::QuarantineList { path } => cmd_quarantine_list(path),
            AdminCommands::QuarantineInspect {
                path,
                quarantine_id,
            } => cmd_quarantine_inspect(path, quarantine_id),
            AdminCommands::QuarantineExport {
                path,
                quarantine_id,
                output,
            } => cmd_quarantine_export(path, quarantine_id, output),
            AdminCommands::QuarantineRemove {
                path,
                quarantine_id,
            } => cmd_quarantine_remove(path, quarantine_id),
            AdminCommands::CompactReceipts { path } => cmd_compact_receipts(path),
        },
    }
}

/// Upper bound on recovery passes for `admin compact-receipts`.
const COMPACT_MAX_PASSES: u32 = 1000;

fn cmd_compact_receipts(path: PathBuf) -> ExitCode {
    let mut queue = match open_or_exit(&path) {
        Ok(q) => q,
        Err(code) => return code,
    };
    let (mut compacted, mut expired, mut errors) = (0, 0, 0);
    for _ in 0..COMPACT_MAX_PASSES {
        let stats = queue.recover(&steadq_core::WorkBudget::default());
        compacted += stats.receipts_compacted;
        expired += stats.receipts_expired;
        errors += stats.errors.len();
        if !stats.budget_exhausted {
            eprintln!("compacted: {compacted} expired: {expired}");
            if errors > 0 {
                eprintln!("{errors} recovery errors");
                return exit(EXIT_IO_FAILURE);
            }
            return exit(EXIT_SUCCESS);
        }
    }
    eprintln!(
        "compacted: {compacted} expired: {expired}; incomplete after {COMPACT_MAX_PASSES} passes, {errors} errors"
    );
    exit(EXIT_IO_FAILURE)
}

fn cmd_quarantine_remove(path: PathBuf, quarantine_id: String) -> ExitCode {
    let qid = match parse_hex_id(&quarantine_id, "quarantine_id") {
        Ok(b) => b,
        Err(code) => return code,
    };
    let queue = match open_or_exit(&path) {
        Ok(q) => q,
        Err(code) => return code,
    };
    match queue.remove_quarantine(&qid) {
        Ok(true) => {
            eprintln!("removed");
            exit(EXIT_SUCCESS)
        }
        Ok(false) => {
            eprintln!("not found");
            exit(EXIT_ORDINARY)
        }
        Err(e) => {
            eprintln!("remove failed: {e}");
            exit_io(&e)
        }
    }
}

fn cmd_quarantine_export(path: PathBuf, quarantine_id: String, output: PathBuf) -> ExitCode {
    let qid = match parse_hex_id(&quarantine_id, "quarantine_id") {
        Ok(b) => b,
        Err(code) => return code,
    };
    let queue = match open_or_exit(&path) {
        Ok(q) => q,
        Err(code) => return code,
    };
    match queue.export_quarantine(&qid, &output) {
        Ok(n) => {
            eprintln!("exported {n} bytes");
            exit(EXIT_SUCCESS)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("not found");
            exit(EXIT_ORDINARY)
        }
        Err(e) => {
            eprintln!("export failed: {e}");
            exit_io(&e)
        }
    }
}

fn cmd_quarantine_inspect(path: PathBuf, quarantine_id: String) -> ExitCode {
    let qid = match parse_hex_id(&quarantine_id, "quarantine_id") {
        Ok(b) => b,
        Err(code) => return code,
    };
    let queue = match open_or_exit(&path) {
        Ok(q) => q,
        Err(code) => return code,
    };
    match queue.find_quarantine(&qid) {
        Some(entry) => {
            let abs = path.join(&entry.relative_path);
            let meta = std::fs::metadata(&abs).ok();
            let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
            println!(
                "quarantine_id={} reason=0x{:04x} path={} size={size}",
                steadq_names::hex_encode(&entry.quarantine_id),
                entry.reason,
                entry.relative_path
            );
            exit(EXIT_SUCCESS)
        }
        None => {
            eprintln!("not found");
            exit(EXIT_ORDINARY)
        }
    }
}

fn cmd_quarantine_list(path: PathBuf) -> ExitCode {
    let queue = match open_or_exit(&path) {
        Ok(q) => q,
        Err(code) => return code,
    };
    for entry in queue.list_quarantine() {
        println!(
            "{} reason=0x{:04x} {}",
            steadq_names::hex_encode(&entry.quarantine_id),
            entry.reason,
            entry.relative_path
        );
    }
    exit(EXIT_SUCCESS)
}

fn cmd_dead_remove(path: PathBuf, job_id: String) -> ExitCode {
    let job_id_bytes = match parse_hex_id(&job_id, "job_id") {
        Ok(b) => b,
        Err(code) => return code,
    };
    let queue = match open_or_exit(&path) {
        Ok(q) => q,
        Err(code) => return code,
    };
    match queue.remove_dead(&job_id_bytes) {
        Ok(true) => {
            eprintln!("removed");
            exit(EXIT_SUCCESS)
        }
        Ok(false) => {
            eprintln!("not found");
            exit(EXIT_ORDINARY)
        }
        Err(steadq_core::Error::QueueCorrupt(_)) => {
            eprintln!("not found");
            exit(EXIT_ORDINARY)
        }
        Err(e) => {
            eprintln!("remove failed: {e}");
            exit_core(&e)
        }
    }
}

fn cmd_dead_export(path: PathBuf, job_id: String, output: PathBuf) -> ExitCode {
    let job_id_bytes = match parse_hex_id(&job_id, "job_id") {
        Ok(b) => b,
        Err(code) => return code,
    };
    let queue = match open_or_exit(&path) {
        Ok(q) => q,
        Err(code) => return code,
    };
    match queue.export_dead(&job_id_bytes, &output) {
        Ok(n) => {
            eprintln!("exported {n} bytes");
            exit(EXIT_SUCCESS)
        }
        Err(steadq_core::Error::QueueCorrupt(_)) => {
            eprintln!("not found");
            exit(EXIT_ORDINARY)
        }
        Err(e) => {
            eprintln!("export failed: {e}");
            exit_core(&e)
        }
    }
}

fn cmd_dead_inspect(path: PathBuf, job_id: String) -> ExitCode {
    let job_id_bytes = match parse_hex_id(&job_id, "job_id") {
        Ok(b) => b,
        Err(code) => return code,
    };
    let queue = match open_or_exit(&path) {
        Ok(q) => q,
        Err(code) => return code,
    };
    for s in queue
        .inspect(&job_id_bytes)
        .iter()
        .filter(|s| s.state == "dead")
    {
        println!(
            "gen={} attempt={}/{} {}",
            s.generation, s.attempt, s.maximum_attempts, s.relative_path
        );
    }
    exit(EXIT_SUCCESS)
}

fn cmd_dead_list(path: PathBuf) -> ExitCode {
    let queue = match open_or_exit(&path) {
        Ok(q) => q,
        Err(code) => return code,
    };
    match queue.list_dead() {
        Ok(entries) => {
            for s in entries {
                println!(
                    "{} gen={} attempt={}/{} {}",
                    steadq_names::hex_encode(&s.job_id),
                    s.generation,
                    s.attempt,
                    s.maximum_attempts,
                    s.relative_path
                );
            }
            exit(EXIT_SUCCESS)
        }
        Err(e) => {
            eprintln!("dead list failed: {e}");
            exit_core(&e)
        }
    }
}

fn cmd_bench(
    path: PathBuf,
    allow_nonempty: bool,
    producers: u32,
    consumers: u32,
    duration_seconds: u64,
    payload_size: usize,
    lease_duration_seconds: u64,
) -> ExitCode {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::thread;

    let Some(lease_ns) = parse_duration_seconds(lease_duration_seconds) else {
        eprintln!("lease duration overflows nanoseconds");
        return exit(EXIT_ORDINARY);
    };
    if !allow_nonempty {
        // Consumers ack whatever they lease, so real jobs would be lost.
        match collect_stats(&path) {
            Ok(stats) => {
                let jobs: usize = ["ready", "leased", "delayed"]
                    .iter()
                    .filter_map(|state| stats.get(state))
                    .map(|s| s.count)
                    .sum();
                if jobs > 0 {
                    eprintln!(
                        "refusing to bench a queue holding {jobs} jobs: bench leases and acks them; pass --allow-nonempty to consume them"
                    );
                    return exit(EXIT_ORDINARY);
                }
            }
            Err(e) => {
                eprintln!("bench: scan {}: {e}", path.display());
                return exit_io(&e);
            }
        }
    }
    eprintln!(
        "bench: {producers} producers, {consumers} consumers, {duration_seconds}s, {payload_size}B payload"
    );

    let payload = vec![0x42u8; payload_size];
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(duration_seconds);
    let open_worker = |p: &PathBuf| {
        Queue::open(
            p,
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
    };

    let enqueued = Arc::new(AtomicU64::new(0));
    let leased = Arc::new(AtomicU64::new(0));
    let acked = Arc::new(AtomicU64::new(0));
    let mut handles: Vec<thread::JoinHandle<Result<(), Error>>> = Vec::new();

    // Producers: reuse one queue handle per worker
    for _ in 0..producers {
        let p = path.clone();
        let payload = payload.clone();
        let enqueued = enqueued.clone();
        handles.push(thread::spawn(move || {
            let mut queue = open_worker(&p)?;
            while std::time::Instant::now() < deadline {
                if let steadq_core::EnqueueOutcome::Committed(_) = queue.enqueue(EnqueueInput {
                    maximum_attempts: 3,
                    content_type: "bench".to_string(),
                    payload: payload.clone(),
                    ..Default::default()
                }) {
                    enqueued.fetch_add(1, Ordering::Relaxed);
                }
            }
            Ok(())
        }));
    }

    // Consumers: reuse one queue handle per worker
    for _ in 0..consumers {
        let p = path.clone();
        let leased = leased.clone();
        let acked = acked.clone();
        handles.push(thread::spawn(move || {
            let mut queue = open_worker(&p)?;
            while std::time::Instant::now() < deadline {
                match queue.lease(0, lease_ns) {
                    steadq_core::LeaseOutcome::Leased(l) => {
                        leased.fetch_add(1, Ordering::Relaxed);
                        if queue.ack(&l) == steadq_core::AckOutcome::Acked {
                            acked.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    _ => thread::sleep(std::time::Duration::from_millis(1)),
                }
            }
            Ok(())
        }));
    }

    let mut failure = None;
    for h in handles {
        match h.join() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                eprintln!("worker open failed: {e}");
                failure.get_or_insert(exit_core(&e));
            }
            Err(_) => {
                eprintln!("worker panicked");
                failure.get_or_insert(exit(EXIT_IO_FAILURE));
            }
        }
    }

    let elapsed = duration_seconds as f64;
    let eq = enqueued.load(Ordering::Relaxed);
    let lq = leased.load(Ordering::Relaxed);
    let aq = acked.load(Ordering::Relaxed);

    eprintln!("enqueued: {} ({:.0}/s)", eq, eq as f64 / elapsed);
    eprintln!("leased: {} ({:.0}/s)", lq, lq as f64 / elapsed);
    eprintln!("acked: {} ({:.0}/s)", aq, aq as f64 / elapsed);
    failure.unwrap_or_else(|| exit(EXIT_SUCCESS))
}

fn cmd_resolve(path: PathBuf, result_file: PathBuf, stabilize: bool) -> ExitCode {
    let data = match std::fs::read(&result_file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("read result file failed: {e}");
            return exit_io(&e);
        }
    };
    let ticket = match steadq_core::TransitionTicket::from_json(&data) {
        Ok(ticket) => ticket,
        Err(error) => {
            eprintln!("invalid transition ticket: {error}");
            return exit(EXIT_ORDINARY);
        }
    };

    let queue = match open_or_exit(&path) {
        Ok(q) => q,
        Err(code) => return code,
    };
    let (source_path, dest_path) = match queue.transition_ticket_paths(&ticket) {
        Ok(paths) => paths,
        Err(error) => {
            eprintln!("invalid transition ticket: {error}");
            return exit(EXIT_ORDINARY);
        }
    };

    let outcome = queue.resolve(&ticket, stabilize);
    match outcome {
        steadq_core::ResolutionOutcome::DestinationObserved
        | steadq_core::ResolutionOutcome::DestinationStabilized => {
            eprintln!("destination observed: {dest_path}");
            exit(EXIT_SUCCESS)
        }
        steadq_core::ResolutionOutcome::SourceObserved
        | steadq_core::ResolutionOutcome::SourceStabilized => {
            eprintln!("source observed: {source_path}");
            exit(EXIT_SUCCESS)
        }
        steadq_core::ResolutionOutcome::BothObserved => {
            eprintln!("both source and destination observed (corruption)");
            exit(EXIT_CORRUPTION)
        }
        steadq_core::ResolutionOutcome::NeitherObserved => {
            eprintln!("neither source nor destination observed");
            exit(EXIT_ORDINARY)
        }
        steadq_core::ResolutionOutcome::ConflictingObject => {
            eprintln!("conflicting object at expected path");
            exit(EXIT_CORRUPTION)
        }
        steadq_core::ResolutionOutcome::ResolutionFailed(e) => {
            eprintln!("resolution failed: {e}");
            exit_core(&e)
        }
    }
}

fn cmd_recover(path: PathBuf, watch: bool, budget_ops: u32, budget_ms: u64) -> ExitCode {
    let budget = steadq_core::WorkBudget {
        max_operations: budget_ops,
        max_duration_ms: budget_ms,
    };
    let mut queue = match open_or_exit(&path) {
        Ok(q) => q,
        Err(code) => return code,
    };
    loop {
        let stats = queue.recover(&budget);
        eprintln!(
            "reaped:{} promoted:{} temp_deleted:{} dead:{} ops:{}{}",
            stats.leases_reaped,
            stats.delayed_promoted,
            stats.temp_files_deleted,
            stats.leases_to_dead,
            stats.operations_attempted,
            if stats.budget_exhausted {
                " (budget exhausted)"
            } else {
                ""
            },
        );
        if !stats.errors.is_empty() {
            eprintln!("{} recovery errors", stats.errors.len());
        }
        if !watch {
            if stats.errors.is_empty() {
                break;
            } else {
                return exit(EXIT_IO_FAILURE);
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
    exit(EXIT_SUCCESS)
}

fn cmd_work(
    path: PathBuf,
    concurrency: u32,
    lease_seconds: u64,
    once: bool,
    command: Vec<String>,
) -> ExitCode {
    let Some(lease_ns) = parse_duration_seconds(lease_seconds) else {
        eprintln!("lease seconds out of range");
        return exit(EXIT_ORDINARY);
    };
    exit(work::run(&path, concurrency, lease_ns, once, &command))
}

/// Why a record file could not be described.
enum RecordError {
    Unrecognized,
    Corrupt(String),
}

/// Decode any SteadQ on-disk record by magic into printable fields.
/// `deep` also verifies a job's payload digest.
fn describe_record(data: &[u8], deep: bool) -> Result<Vec<(&'static str, String)>, RecordError> {
    let hex = steadq_names::hex_encode;
    let magic = data.get(..8).ok_or(RecordError::Unrecognized)?;
    let corrupt = |e: &dyn std::fmt::Display| RecordError::Corrupt(e.to_string());
    if magic == steadq_format::JOB_MAGIC {
        let envelope =
            steadq_format::ValidatedEnvelope::from_bytes(data, deep).map_err(|e| corrupt(&e))?;
        let h = envelope.header;
        let mut fields = vec![
            ("type", "job".to_string()),
            ("job_id", hex(&h.job_id)),
            ("payload_length", h.payload_length.to_string()),
            (
                "extension_header_length",
                h.extension_header_length.to_string(),
            ),
            ("maximum_attempts", h.maximum_attempts.to_string()),
            ("payload_digest", hex(&h.payload_digest)),
            (
                "envelope_digest",
                format!("{} (verified)", hex(&h.envelope_digest)),
            ),
        ];
        if deep {
            fields.push(("payload_digest_verified", "true".to_string()));
        }
        return Ok(fields);
    }
    if magic == steadq_format::FORMAT_MAGIC {
        let f = steadq_format::FormatRecord::decode(data).map_err(|e| corrupt(&e))?;
        return Ok(vec![
            ("type", "format".to_string()),
            ("queue_id", hex(f.queue_id())),
            ("shard_count", f.shard_count().to_string()),
            (
                "lease_bucket_width_ns",
                f.lease_bucket_width_ns().to_string(),
            ),
            (
                "delayed_bucket_width_ns",
                f.delayed_bucket_width_ns().to_string(),
            ),
            (
                "terminal_bucket_width_ns",
                f.terminal_bucket_width_ns().to_string(),
            ),
            ("max_payload_length", f.max_payload_length().to_string()),
        ]);
    }
    if magic == steadq_format::RECEIPT_MAGIC {
        let r = steadq_format::CompactReceipt::decode(data).map_err(|e| corrupt(&e))?;
        return Ok(vec![
            ("type", "receipt".to_string()),
            ("job_id", hex(&r.job_id)),
            ("envelope_digest", hex(&r.envelope_digest)),
            ("final_attempt", r.final_attempt.to_string()),
            ("lease_token", hex(&r.lease_token)),
            (
                "receipt_bucket_start_unix_ns",
                r.receipt_bucket_start_unix_ns.to_string(),
            ),
            (
                "original_payload_length",
                r.original_payload_length.to_string(),
            ),
        ]);
    }
    if magic == steadq_format::WATERMARK_MAGIC {
        let w = steadq_format::WatermarkRecord::decode(data).map_err(|e| corrupt(&e))?;
        return Ok(vec![
            ("type", "watermark".to_string()),
            (
                "highest_observed_bucket",
                w.highest_observed_bucket.to_string(),
            ),
            ("sequence", w.sequence.to_string()),
        ]);
    }
    Err(RecordError::Unrecognized)
}

fn cmd_format_dump(file: PathBuf) -> ExitCode {
    let data = match std::fs::read(&file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("read failed: {e}");
            return exit_io(&e);
        }
    };
    match describe_record(&data, false) {
        Ok(fields) => {
            for (key, value) in fields {
                println!("{key}: {value}");
            }
            exit(EXIT_SUCCESS)
        }
        Err(RecordError::Corrupt(e)) => {
            eprintln!("parse error: {e}");
            exit(EXIT_ORDINARY)
        }
        Err(RecordError::Unrecognized) => {
            eprintln!("unrecognized format");
            exit(EXIT_ORDINARY)
        }
    }
}

fn cmd_verify(file: PathBuf, deep: bool) -> ExitCode {
    let data = match std::fs::read(&file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("read failed: {e}");
            return exit_io(&e);
        }
    };
    match describe_record(&data, deep) {
        Ok(fields) => {
            for (key, value) in fields {
                println!("{key}: {value}");
            }
            eprintln!("valid");
            exit(EXIT_SUCCESS)
        }
        Err(RecordError::Corrupt(e)) => {
            eprintln!("CORRUPT: {e}");
            exit(EXIT_CORRUPTION)
        }
        Err(RecordError::Unrecognized) => {
            eprintln!("unknown format");
            exit(EXIT_ORDINARY)
        }
    }
}

fn cmd_inspect(path: PathBuf, job_id: String) -> ExitCode {
    let job_id_bytes = match parse_hex_id(&job_id, "job_id") {
        Ok(b) => b,
        Err(code) => return code,
    };
    let queue = match open_or_exit(&path) {
        Ok(q) => q,
        Err(code) => return code,
    };
    let snapshots = queue.inspect(&job_id_bytes);
    if snapshots.is_empty() {
        eprintln!("not found");
        return exit(EXIT_ORDINARY);
    }
    for s in &snapshots {
        println!(
            "{} gen={} attempt={}/{} {}",
            s.state, s.generation, s.attempt, s.maximum_attempts, s.relative_path
        );
    }
    exit(EXIT_SUCCESS)
}

/// Dead reason names from spec/reasons.md, indexed by code.
const DEAD_REASON_NAMES: [&str; 5] = [
    "unspecified",
    "consumer_rejected",
    "unsupported_content_type",
    "administrative_bury",
    "attempts_exhausted",
];

/// Parse a dead reason by name or decimal code.
fn parse_dead_reason(value: &str) -> Option<steadq_core::DeadReason> {
    let code = match DEAD_REASON_NAMES.iter().position(|name| *name == value) {
        Some(index) => index as u16,
        None => value.parse().ok()?,
    };
    steadq_core::DeadReason::from_u16(code)
}

/// Open the queue and load the lease handle bound to it.
fn open_with_handle(
    path: &std::path::Path,
    handle_file: &std::path::Path,
) -> Result<(Queue, steadq_core::LeaseInfo), ExitCode> {
    let queue = open_or_exit(path)?;
    match load_handle(handle_file, path, queue.format().queue_id()) {
        Ok(lease) => Ok((queue, lease)),
        Err(e) => {
            eprintln!("handle load failed: {e}");
            Err(exit_io(&e))
        }
    }
}

/// Report an indeterminate transition and persist its ticket for
/// `steadq resolve` when a path was given.
fn exit_unknown(
    ticket: &steadq_core::TransitionTicket,
    ticket_out: Option<&std::path::Path>,
) -> ExitCode {
    eprintln!("outcome unknown");
    eprintln!("job_id: {}", steadq_names::hex_encode(&ticket.job_id()));
    if let Some(path) = ticket_out {
        match write_ticket_file(path, ticket) {
            Ok(()) => eprintln!("ticket written to: {}", path.display()),
            Err(e) => eprintln!("warning: failed to write ticket: {e}"),
        }
    }
    exit(EXIT_INDETERMINATE)
}

fn cmd_bury(
    path: PathBuf,
    handle_file: PathBuf,
    reason: String,
    ticket_out: Option<PathBuf>,
) -> ExitCode {
    let Some(reason) = parse_dead_reason(&reason) else {
        eprintln!(
            "invalid dead reason {reason:?}: expected 0-4 or one of {}",
            DEAD_REASON_NAMES.join(", ")
        );
        return exit(EXIT_ORDINARY);
    };
    let (mut queue, lease) = match open_with_handle(&path, &handle_file) {
        Ok(opened) => opened,
        Err(code) => return code,
    };
    match queue.bury(&lease, reason) {
        steadq_core::TransitionOutcome::Committed => {
            eprintln!("buried");
            exit(EXIT_SUCCESS)
        }
        steadq_core::TransitionOutcome::LeaseLost => {
            eprintln!("lease lost");
            exit(EXIT_ORDINARY)
        }
        steadq_core::TransitionOutcome::NotCommitted(e) => {
            eprintln!("not committed: {e}");
            exit_core(&e)
        }
        steadq_core::TransitionOutcome::OutcomeUnknown(ticket) => {
            exit_unknown(&ticket, ticket_out.as_deref())
        }
    }
}

fn cmd_retry(
    path: PathBuf,
    handle_file: PathBuf,
    after_seconds: Option<u64>,
    ticket_out: Option<PathBuf>,
) -> ExitCode {
    let (mut queue, lease) = match open_with_handle(&path, &handle_file) {
        Ok(opened) => opened,
        Err(code) => return code,
    };
    // retry_after() uses the rollback-safe effective wall clock.
    let outcome = match after_seconds {
        Some(s) => {
            let duration_ns = s.saturating_mul(1_000_000_000);
            queue.retry_after(&lease, duration_ns)
        }
        None => queue.retry_now(&lease),
    };
    match outcome {
        steadq_core::TransitionOutcome::Committed => {
            eprintln!("retried");
            exit(EXIT_SUCCESS)
        }
        steadq_core::TransitionOutcome::LeaseLost => {
            eprintln!("lease lost");
            exit(EXIT_ORDINARY)
        }
        steadq_core::TransitionOutcome::NotCommitted(e) => {
            eprintln!("not committed: {e}");
            exit_core(&e)
        }
        steadq_core::TransitionOutcome::OutcomeUnknown(ticket) => {
            exit_unknown(&ticket, ticket_out.as_deref())
        }
    }
}

fn cmd_ack(path: PathBuf, handle_file: PathBuf, ticket_out: Option<PathBuf>) -> ExitCode {
    let (mut queue, lease) = match open_with_handle(&path, &handle_file) {
        Ok(opened) => opened,
        Err(code) => return code,
    };
    // ack() performs strict payload verification; no separate
    // verify_lease_payload() call (avoids double hashing).
    match queue.ack(&lease) {
        steadq_core::AckOutcome::Acked => {
            eprintln!("acked");
            exit(EXIT_SUCCESS)
        }
        steadq_core::AckOutcome::AlreadyAcked => {
            eprintln!("already acked (idempotent success)");
            exit(EXIT_SUCCESS)
        }
        steadq_core::AckOutcome::LeaseLost => {
            eprintln!("lease lost");
            exit(EXIT_ORDINARY)
        }
        steadq_core::AckOutcome::NotCommitted(e) => {
            eprintln!("not committed: {e}");
            exit_core(&e)
        }
        steadq_core::AckOutcome::OutcomeUnknown(ticket) => {
            exit_unknown(&ticket, ticket_out.as_deref())
        }
    }
}

fn cmd_doctor(path: PathBuf, json: bool) -> ExitCode {
    let mut results: Vec<(&str, String, bool)> = Vec::new();
    let mut unsupported_fs = false;

    // boot_id
    match steadq_fs_linux::read_boot_id() {
        Ok(id) => results.push(("boot_id", id, true)),
        Err(e) => results.push(("boot_id", e.to_string(), false)),
    }
    // clock_boottime
    match steadq_fs_linux::clock_boottime_ns() {
        Ok(ns) => results.push(("clock_boottime", format!("{ns} ns"), true)),
        Err(e) => results.push(("clock_boottime", e.to_string(), false)),
    }
    // clock_realtime
    match steadq_fs_linux::clock_realtime_ns() {
        Ok(ns) => results.push(("clock_realtime", format!("{ns} ns"), true)),
        Err(e) => results.push(("clock_realtime", e.to_string(), false)),
    }
    // getrandom
    match steadq_fs_linux::random_128bit() {
        Ok(_) => results.push(("getrandom", "OK".to_string(), true)),
        Err(e) => results.push(("getrandom", e.to_string(), false)),
    }

    if path.exists() {
        // filesystem type
        match steadq_fs_linux::fs_type_magic(&path) {
            Ok(ft) => {
                let (fs_name, fs_ok) = doctor_filesystem(ft);
                unsupported_fs = !fs_ok;
                results.push(("filesystem", format!("{fs_name} (magic {ft:#x})"), fs_ok));
            }
            Err(e) => results.push(("filesystem", e.to_string(), false)),
        }

        // Publication mode probe under tmp/
        let probe_dir = path.join("tmp");
        if probe_dir.exists() {
            match steadq_fs_linux::open_dir_absolute(&probe_dir) {
                Ok(dir_fd) => {
                    match steadq_fs_linux::probe_publication_mode(dir_fd.as_fd()) {
                        Ok(mode) => {
                            let mode_str = match mode {
                                steadq_fs_linux::PublicationMode::DirectAtEmptyPath => {
                                    "direct-at-empty-path"
                                }
                                steadq_fs_linux::PublicationMode::ProcSelfFd => "proc-self-fd",
                                steadq_fs_linux::PublicationMode::NamedFallback => "named-fallback",
                            };
                            results.push(("publication_mode", mode_str.to_string(), true));
                        }
                        Err(e) => results.push(("publication_mode", e.to_string(), false)),
                    }
                    // rename probe
                    match steadq_fs_linux::probe_rename_noreplace(dir_fd.as_fd()) {
                        Ok(supported) => results.push((
                            "rename_noreplace",
                            if supported {
                                "supported".into()
                            } else {
                                "unsupported".into()
                            },
                            supported,
                        )),
                        Err(e) => results.push(("rename_noreplace", e.to_string(), false)),
                    }
                    // dir fsync probe
                    match steadq_fs_linux::probe_dir_fsync(dir_fd.as_fd()) {
                        Ok(supported) => results.push((
                            "dir_fsync",
                            if supported {
                                "supported".into()
                            } else {
                                "unsupported".into()
                            },
                            supported,
                        )),
                        Err(e) => results.push(("dir_fsync", e.to_string(), false)),
                    }
                }
                Err(e) => results.push(("publication_mode", format!("open failed: {e}"), false)),
            }
        }
    }

    if json {
        let map: std::collections::BTreeMap<&str, serde_json::Value> = results
            .iter()
            .map(|(k, v, ok)| (*k, serde_json::json!({"value": v, "ok": ok})))
            .collect();
        println!("{}", serde_json::to_string_pretty(&map).unwrap());
    } else {
        eprintln!("steadq doctor {}", path.display());
        for (k, v, ok) in &results {
            eprintln!("  {}: {}{}", k, v, if *ok { "" } else { " [FAIL]" });
        }
    }
    if results.iter().all(|(_, _, ok)| *ok) {
        exit(EXIT_SUCCESS)
    } else if unsupported_fs {
        exit(EXIT_UNSUPPORTED)
    } else {
        exit(EXIT_IO_FAILURE)
    }
}

fn cmd_fsck(path: PathBuf, deep: bool, repair: bool) -> ExitCode {
    let queue = match open_or_exit(&path) {
        Ok(q) => q,
        Err(code) => return code,
    };
    let opts = FsckOptions {
        mode: if repair {
            FsckMode::Repair
        } else {
            FsckMode::Check
        },
        depth: if deep {
            FsckDepth::Deep
        } else {
            FsckDepth::Structural
        },
    };
    let report = queue.fsck(&opts);
    eprintln!(
        "objects: {}, structurally verified: {}, payload verified: {}",
        report.total_objects, report.structurally_verified, report.payloads_deep_verified
    );
    for finding in &report.findings {
        let severity = match finding.severity {
            FindingSeverity::Error => "ERROR",
            FindingSeverity::Warning => "WARN",
        };
        println!(
            "{severity} {}: {} ({})",
            finding.relative_path, finding.finding_type, finding.details
        );
    }
    if !report.quarantined.is_empty() {
        eprintln!("quarantined: {}", report.quarantined.len());
    }
    let has_errors = report
        .findings
        .iter()
        .any(|f| f.severity == FindingSeverity::Error);
    if has_errors {
        exit(EXIT_CORRUPTION)
    } else {
        exit(EXIT_SUCCESS)
    }
}

fn cmd_stats(path: PathBuf, prometheus: bool, json: bool) -> ExitCode {
    if let Err(code) = open_or_exit(&path) {
        return code;
    }
    let stats_map = match collect_stats(&path) {
        Ok(stats) => stats,
        Err(e) => {
            eprintln!("stats: {}: {e}", path.display());
            return exit_io(&e);
        }
    };
    if prometheus {
        for (state, stats) in &stats_map {
            println!("# TYPE steadq_{state}_objects gauge");
            println!("steadq_{state}_objects {}", stats.count);
        }
        for (state, stats) in &stats_map {
            if let Some(oldest) = stats.oldest {
                println!("# TYPE steadq_{state}_oldest_age_seconds gauge");
                println!("steadq_{state}_oldest_age_seconds {}", age_seconds(oldest));
            }
        }
    } else if json {
        let plain: std::collections::BTreeMap<&str, serde_json::Value> = stats_map
            .iter()
            .map(|(state, stats)| {
                (
                    *state,
                    serde_json::json!({
                        "objects": stats.count,
                        "oldest_age_seconds": stats.oldest.map(age_seconds),
                    }),
                )
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&plain).unwrap());
    } else {
        for (state, stats) in &stats_map {
            match stats.oldest {
                Some(oldest) => {
                    println!("{state}: {} (oldest {}s)", stats.count, age_seconds(oldest))
                }
                None => println!("{state}: {}", stats.count),
            }
        }
    }
    exit(EXIT_SUCCESS)
}

fn cmd_lease(
    path: PathBuf,
    duration_seconds: u64,
    handle_file: Option<PathBuf>,
    ticket_out: Option<PathBuf>,
) -> ExitCode {
    let queue = match open_or_exit(&path) {
        Ok(q) => q,
        Err(code) => return code,
    };
    let mut queue = queue;

    let duration_ns = match parse_duration_seconds(duration_seconds) {
        Some(ns) => ns,
        None => {
            eprintln!("invalid duration: overflow");
            return exit(EXIT_ORDINARY);
        }
    };
    match queue.lease(0, duration_ns) {
        LeaseOutcome::Leased(lease) => {
            let summary = format!(
                "job_id: {}\ngeneration: {}\nattempt: {}/{}",
                steadq_names::hex_encode(&lease.job_id),
                lease.generation,
                lease.attempt,
                lease.maximum_attempts
            );
            let handle = handle_json(&path, queue.format().queue_id(), &lease);
            match (handle, handle_file) {
                (Ok(handle), Some(hf)) => {
                    if let Err(e) = atomic_write_private(&hf, handle.as_bytes()) {
                        eprintln!("failed to write handle file: {e}");
                        return exit_io(&e);
                    }
                    println!("{summary}");
                }
                // The lease consumed an attempt; hand the caller the handle
                // on stdout so the job can still be acked or retried.
                (Ok(handle), None) => {
                    println!("{handle}");
                    eprintln!("{summary}");
                }
                (Err(e), _) => {
                    eprintln!("{summary}");
                    eprintln!("failed to encode handle: {e}");
                    return exit_io(&e);
                }
            }
            exit(EXIT_SUCCESS)
        }
        LeaseOutcome::Empty => {
            eprintln!("no jobs available");
            exit(EXIT_ORDINARY)
        }
        LeaseOutcome::NotCommitted(e) => {
            eprintln!("lease failed: {e}");
            exit_core(&e)
        }
        LeaseOutcome::OutcomeUnknown(ticket) => exit_unknown(&ticket, ticket_out.as_deref()),
    }
}

fn cmd_put(
    path: PathBuf,
    file: Option<String>,
    content_type: String,
    max_attempts: u32,
    not_before: Option<u64>,
    producer_id: Option<String>,
) -> ExitCode {
    // Fail on read error rather than enqueueing an empty payload
    let payload = match file.as_deref() {
        Some("-") | None => {
            use std::io::Read;
            let mut buf = Vec::new();
            match std::io::stdin().read_to_end(&mut buf) {
                Ok(_) => buf,
                Err(e) => {
                    eprintln!("stdin read failed: {e}");
                    return exit_io(&e);
                }
            }
        }
        Some(f) => match std::fs::read(f) {
            Ok(data) => data,
            Err(e) => {
                eprintln!("file read failed: {e}");
                return exit_io(&e);
            }
        },
    };

    let queue = match open_or_exit(&path) {
        Ok(q) => q,
        Err(code) => return code,
    };
    let mut queue = queue;

    let input = steadq_core::EnqueueInput {
        maximum_attempts: max_attempts,
        content_type,
        payload,
        initial_not_before: not_before,
        producer_id,
        ..Default::default()
    };

    match queue.enqueue(input) {
        EnqueueOutcome::Committed(ticket) => {
            println!("job_id: {}", steadq_names::hex_encode(&ticket.job_id));
            println!("path: {}", ticket.expected_relative_path);
            exit(EXIT_SUCCESS)
        }
        EnqueueOutcome::Deferred(ticket) => {
            eprintln!("durability deferred; operation is not committed");
            eprintln!("job_id: {}", steadq_names::hex_encode(&ticket.job_id));
            eprintln!("path: {}", ticket.expected_relative_path);
            exit(EXIT_INDETERMINATE)
        }
        EnqueueOutcome::NotCommitted(ticket, err) => {
            eprintln!("not committed: {err}");
            if ticket.job_id != [0; 16] {
                eprintln!("job_id: {}", steadq_names::hex_encode(&ticket.job_id));
            }
            exit_core(&err)
        }
        EnqueueOutcome::OutcomeUnknown(ticket, err) => {
            eprintln!("outcome unknown: {err}");
            eprintln!("job_id: {}", steadq_names::hex_encode(&ticket.job_id));
            eprintln!("path: {}", ticket.expected_relative_path);
            exit(EXIT_INDETERMINATE)
        }
    }
}

fn cmd_init(path: PathBuf, shards: u32, terminal_bucket_width_ns: u64) -> ExitCode {
    let opts = CreateOptions {
        shard_count: shards,
        terminal_bucket_width_ns,
        ..Default::default()
    };
    match Queue::init(&path, &opts) {
        Ok(format) => {
            eprintln!("initialized queue at {}", path.display());
            eprintln!("queue_id: {}", steadq_names::hex_encode(format.queue_id()));
            eprintln!("shards: {}", format.shard_count());
            exit(EXIT_SUCCESS)
        }
        Err(e) => {
            eprintln!("init failed: {e}");
            exit_io(&e)
        }
    }
}

/// Per-state object count and oldest mtime.
#[derive(Default)]
struct StateStats {
    count: usize,
    oldest: Option<std::time::SystemTime>,
}

impl StateStats {
    fn add(&mut self, modified: Option<std::time::SystemTime>) {
        self.count += 1;
        self.oldest = [self.oldest, modified].into_iter().flatten().min();
    }
}

/// Count objects per state directory. A live lease keeps its file in
/// ready/<shard>/ under a leased name, so ready/ entries whose name parses
/// as leased count as leased, together with the legacy leased/ tree.
/// Returns Err when a directory cannot be listed: "unreadable" must not
/// read as "empty" on a monitoring surface.
fn collect_stats(
    root: &std::path::Path,
) -> std::io::Result<std::collections::BTreeMap<&'static str, StateStats>> {
    use steadq_names::State;
    let mut map = std::collections::BTreeMap::new();
    for state in [
        State::Ready,
        State::Leased,
        State::Delayed,
        State::Receipt,
        State::Dead,
        State::Quarantine,
    ] {
        let dir = root.join(state.dir_name());
        if !dir.exists() {
            continue;
        }
        map.entry(state.dir_name())
            .or_insert_with(StateStats::default);
        walk_stats(&dir, &mut |name, modified| {
            let bucket = if state == State::Ready && steadq_names::parse_leased(name).is_ok() {
                State::Leased.dir_name()
            } else {
                state.dir_name()
            };
            map.entry(bucket)
                .or_insert_with(StateStats::default)
                .add(modified);
        })?;
    }
    Ok(map)
}

/// Visit every non-directory entry below `path` with its name and mtime.
/// A directory or entry that vanishes mid-walk (recovery removes emptied
/// receipt and bucket directories) is absent, not an error.
fn walk_stats(
    path: &std::path::Path,
    visit: &mut dyn FnMut(&str, Option<std::time::SystemTime>),
) -> std::io::Result<()> {
    let entries = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    for entry in entries {
        let entry = entry?;
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        if metadata.is_dir() {
            walk_stats(&entry.path(), visit)?;
        } else {
            visit(
                &entry.file_name().to_string_lossy(),
                metadata.modified().ok(),
            );
        }
    }
    Ok(())
}

fn age_seconds(since: std::time::SystemTime) -> u64 {
    std::time::SystemTime::now()
        .duration_since(since)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct HandleFile {
    queue_root: String,
    #[serde(default)]
    queue_id: Option<String>,
    job_id: String,
    generation: u64,
    attempt: u32,
    maximum_attempts: u32,
    token: String,
    boot_id: String,
    expires_boottime_ns: u64,
    expires_wall_ns: u64,
    expected_dev: u64,
    expected_inode: u64,
    exact_source_path: String,
    envelope_digest: String,
    content_type: String,
    payload_length: u64,
    payload_digest: String,
}

/// Write `bytes` to `path` through a private temp file and rename, then sync
/// the parent directory on a best-effort basis.
fn atomic_write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let rand_bytes = steadq_fs_linux::random_128bit()
        .map(|b| steadq_names::hex_encode(&b))
        .unwrap_or_else(|_| format!("{}", std::process::id()));
    let tmp_path = path.with_extension(format!("tmp.{rand_bytes}"));
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp_path)
        .and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()
        })
        .and_then(|()| std::fs::rename(&tmp_path, path));
    if let Err(error) = written {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(error);
    }
    if let Some(parent) = path.parent() {
        if let Ok(parent_dir) = std::fs::File::open(parent) {
            let _ = parent_dir.sync_all();
        }
    }
    Ok(())
}

fn write_ticket_file(
    path: &std::path::Path,
    ticket: &steadq_core::TransitionTicket,
) -> std::io::Result<()> {
    let json = ticket
        .to_json()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()))?;
    atomic_write_private(path, &json)
}

fn invalid_data(message: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

/// Serialize a lease handle bound to the queue's identity and canonical root.
fn handle_json(
    queue_root: &std::path::Path,
    queue_id: &[u8; 16],
    lease: &steadq_core::LeaseInfo,
) -> std::io::Result<String> {
    let handle = HandleFile {
        queue_root: std::fs::canonicalize(queue_root)?.display().to_string(),
        queue_id: Some(steadq_names::hex_encode(queue_id)),
        job_id: steadq_names::hex_encode(&lease.job_id),
        generation: lease.generation,
        attempt: lease.attempt,
        maximum_attempts: lease.maximum_attempts,
        token: steadq_names::hex_encode(&lease.token),
        boot_id: lease.boot_id.clone(),
        expires_boottime_ns: lease.expires_boottime_ns,
        expires_wall_ns: lease.expires_wall_ns,
        expected_dev: lease.expected_dev,
        expected_inode: lease.expected_inode,
        exact_source_path: lease.exact_source_path.clone(),
        envelope_digest: steadq_names::hex_encode(&lease.envelope_digest),
        content_type: lease.content_type.clone(),
        payload_length: lease.payload_length,
        payload_digest: steadq_names::hex_encode(&lease.payload_digest),
    };
    Ok(serde_json::to_string_pretty(&handle)?)
}

fn load_handle(
    path: &std::path::Path,
    queue_root: &std::path::Path,
    queue_id: &[u8; 16],
) -> std::io::Result<steadq_core::LeaseInfo> {
    let data = std::fs::read(path)?;
    let handle: HandleFile = serde_json::from_slice(&data)
        .map_err(|e| invalid_data(format!("invalid handle file: {e}")))?;
    // A copied queue keeps its queue_id and its leased files, so only the
    // root tells a handle for the original from one for the copy.
    let issued_for = std::fs::canonicalize(&handle.queue_root).map_err(|e| {
        invalid_data(format!(
            "handle file queue_root {} does not resolve: {e}",
            handle.queue_root
        ))
    })?;
    if issued_for != std::fs::canonicalize(queue_root)? {
        return Err(invalid_data(format!(
            "handle file was issued for the queue at {}",
            handle.queue_root
        )));
    }

    let job_id = steadq_names::hex_decode_16(&handle.job_id)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad job_id"))?;
    let token = steadq_names::hex_decode_16(&handle.token)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad token"))?;
    let envelope_digest =
        steadq_names::hex_decode_32(&handle.envelope_digest).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bad envelope_digest: expected 64 lowercase hex chars",
            )
        })?;
    let payload_digest = steadq_names::hex_decode_32(&handle.payload_digest).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bad payload_digest: expected 64 lowercase hex chars",
        )
    })?;

    // Verify queue binding: queue_id must be present and match.
    match handle.queue_id.as_ref() {
        Some(hqid) => match steadq_names::hex_decode_16(hqid) {
            Some(handle_qid) if handle_qid == *queue_id => {}
            Some(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "handle file queue_id does not match target queue",
                ));
            }
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "handle file queue_id is not 32 lowercase hex chars",
                ));
            }
        },
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "handle file missing queue_id binding",
            ));
        }
    }

    Ok(steadq_core::LeaseInfo {
        job_id,
        envelope_digest,
        generation: handle.generation,
        attempt: handle.attempt,
        maximum_attempts: handle.maximum_attempts,
        token,
        boot_id: handle.boot_id,
        expires_boottime_ns: handle.expires_boottime_ns,
        expires_wall_ns: handle.expires_wall_ns,
        content_type: handle.content_type,
        payload_length: handle.payload_length,
        payload_digest,
        expected_dev: handle.expected_dev,
        expected_inode: handle.expected_inode,
        exact_source_path: handle.exact_source_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_follow_spec_table() {
        for kind in [
            std::io::ErrorKind::StorageFull,
            std::io::ErrorKind::QuotaExceeded,
        ] {
            assert_eq!(
                exit_io(&std::io::Error::from(kind)),
                exit(EXIT_RESOURCE_EXHAUSTED)
            );
        }
        assert_eq!(
            exit_core(&Error::InvalidInput("x".into())),
            exit(EXIT_ORDINARY)
        );
        assert_eq!(
            exit_core(&Error::QueueCorrupt("x".into())),
            exit(EXIT_CORRUPTION)
        );
        assert_eq!(
            exit_core(&Error::UnsupportedFilesystem),
            exit(EXIT_UNSUPPORTED)
        );
        assert_eq!(exit_core(&Error::PermissionDenied), exit(EXIT_PERMISSION));
        assert_eq!(
            exit_core(&Error::ResourceExhausted),
            exit(EXIT_RESOURCE_EXHAUSTED)
        );
        assert_eq!(
            exit_core(&Error::IoFailure("x".into())),
            exit(EXIT_IO_FAILURE)
        );
        assert_eq!(
            exit_io(&std::io::Error::new(std::io::ErrorKind::Unsupported, "fs")),
            exit(EXIT_UNSUPPORTED)
        );
        assert_eq!(
            exit_io(&std::io::Error::new(std::io::ErrorKind::InvalidData, "bad")),
            exit(EXIT_ORDINARY)
        );
        assert_eq!(exit_io(&std::io::Error::other("io")), exit(EXIT_IO_FAILURE));
    }

    #[test]
    fn doctor_accepts_supported_filesystems_including_zfs() {
        assert_eq!(
            doctor_filesystem(steadq_fs_linux::EXT4_SUPER_MAGIC),
            ("ext4", true)
        );
        assert_eq!(
            doctor_filesystem(steadq_fs_linux::F2FS_STATFS_MAGIC_ALT),
            ("f2fs", true)
        );
        assert_eq!(
            doctor_filesystem(steadq_fs_linux::ZFS_SUPER_MAGIC),
            ("zfs", true)
        );
        assert_eq!(
            doctor_filesystem(steadq_fs_linux::TMPFS_MAGIC),
            ("tmpfs_not_certified", false)
        );
    }

    fn sample_lease() -> steadq_core::LeaseInfo {
        steadq_core::LeaseInfo {
            job_id: [0x22; 16],
            envelope_digest: [0x33; 32],
            generation: 1,
            attempt: 1,
            maximum_attempts: 3,
            token: [0x44; 16],
            boot_id: "boot".into(),
            expires_boottime_ns: 10,
            expires_wall_ns: 20,
            content_type: "text/plain".into(),
            payload_length: 11,
            payload_digest: [0x55; 32],
            expected_dev: 1,
            expected_inode: 2,
            exact_source_path: "leased/a/b/c.sqj".into(),
        }
    }

    #[test]
    fn handle_file_roundtrip_preserves_payload_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("q");
        std::fs::create_dir(&root).unwrap();
        let handle_path = tmp.path().join("handle.json");
        let queue_id = [0x11u8; 16];
        let json = handle_json(&root, &queue_id, &sample_lease()).unwrap();
        atomic_write_private(&handle_path, json.as_bytes()).unwrap();
        // The same queue through a non-canonical path still matches.
        let loaded = load_handle(&handle_path, &root.join("."), &queue_id).unwrap();
        assert_eq!(loaded.payload_length, 11);
        assert_eq!(loaded.payload_digest, [0x55; 32]);
        assert_eq!(loaded.content_type, "text/plain");
        assert_eq!(loaded.envelope_digest, [0x33; 32]);
        assert_eq!(loaded.job_id, [0x22; 16]);
    }

    #[test]
    fn handle_for_another_queue_root_or_malformed_is_invalid_data() {
        let tmp = tempfile::tempdir().unwrap();
        let (root, copy) = (tmp.path().join("q"), tmp.path().join("copy"));
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&copy).unwrap();
        let queue_id = [0x11u8; 16];
        let handle_path = tmp.path().join("handle.json");
        let json = handle_json(&root, &queue_id, &sample_lease()).unwrap();
        std::fs::write(&handle_path, &json).unwrap();
        let error = load_handle(&handle_path, &copy, &queue_id).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            error.to_string().contains("issued for the queue at"),
            "{error}"
        );

        std::fs::remove_dir(&root).unwrap();
        let error = load_handle(&handle_path, &copy, &queue_id).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

        // Truncated JSON is EOF to serde; it must still read as bad input.
        std::fs::write(&handle_path, &json[..json.len() / 2]).unwrap();
        let error = load_handle(&handle_path, &copy, &queue_id).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            error.to_string().starts_with("invalid handle file"),
            "{error}"
        );
    }

    #[test]
    fn dead_reason_accepts_names_and_codes_only_from_the_registry() {
        use steadq_core::DeadReason;
        assert_eq!(parse_dead_reason("0"), Some(DeadReason::Unspecified));
        assert_eq!(parse_dead_reason("4"), Some(DeadReason::AttemptsExhausted));
        assert_eq!(
            parse_dead_reason("administrative_bury"),
            Some(DeadReason::AdministrativeBury)
        );
        for bad in ["5", "65537", "-1", "", "Unspecified", "0x0001"] {
            assert_eq!(parse_dead_reason(bad), None, "{bad}");
        }
    }

    #[test]
    fn walk_stats_treats_vanished_directories_as_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let mut visits = 0;
        walk_stats(&tmp.path().join("gone"), &mut |_, _| visits += 1).unwrap();
        assert_eq!(visits, 0);

        // Whichever subdirectory is visited first removes both; the other
        // is already listed and must be skipped, not reported as an error.
        for dir in ["a", "b"] {
            std::fs::create_dir(tmp.path().join(dir)).unwrap();
            std::fs::write(tmp.path().join(dir).join("f"), b"x").unwrap();
        }
        let root = tmp.path().to_path_buf();
        walk_stats(tmp.path(), &mut |_, _| {
            visits += 1;
            for dir in ["a", "b"] {
                let _ = std::fs::remove_dir_all(root.join(dir));
            }
        })
        .unwrap();
        assert_eq!(visits, 1);
    }

    #[test]
    fn collect_stats_counts_colocated_leases_as_leased() {
        let tmp = tempfile::tempdir().unwrap();
        let shard = tmp.path().join("ready").join("00");
        std::fs::create_dir_all(&shard).unwrap();
        std::fs::create_dir_all(tmp.path().join("leased")).unwrap();
        std::fs::write(shard.join("not-a-leased-name.sqj"), b"x").unwrap();
        let stats = collect_stats(tmp.path()).unwrap();
        assert_eq!(stats["ready"].count, 1);
        assert_eq!(stats["leased"].count, 0);
    }

    #[test]
    fn state_stats_oldest_is_global_min_across_sibling_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        for (dir, name, age) in [("a", "f1", 3600), ("a", "f2", 60), ("b", "f3", 7200)] {
            let d = root.join(dir);
            std::fs::create_dir_all(&d).unwrap();
            let f = d.join(name);
            std::fs::write(&f, b"x").unwrap();
            let old = std::time::SystemTime::now() - std::time::Duration::from_secs(age);
            let ft = std::fs::File::options().write(true).open(&f).unwrap();
            ft.set_modified(old).unwrap();
        }
        let mut stats = StateStats::default();
        walk_stats(root, &mut |_, modified| stats.add(modified)).unwrap();
        assert_eq!(stats.count, 3);

        // The oldest file lives in dir b, not the first-listed dir a: the
        // merge must be a min across siblings, not first-wins.
        let age = age_seconds(stats.oldest.unwrap());
        assert!((7100..=7300).contains(&age), "age: {age}");
    }
}
