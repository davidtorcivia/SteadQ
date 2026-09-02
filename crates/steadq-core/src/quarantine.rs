// SteadQ/1 quarantine and fsck operations.

use std::os::unix::io::{AsFd, BorrowedFd};

use sha2::Digest;
use steadq_fs_linux as fs;
use steadq_names;

use crate::queue::engine::{move_verified_noreplace, MoveFailure};
use crate::queue::Queue;

const QUARANTINE_NAME_ATTEMPTS: usize = 8;

fn quarantine_destination_collision(failure: &MoveFailure) -> bool {
    matches!(failure, MoveFailure::AlreadyExists)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QuarantinePreparePhase {
    AttemptBudget,
    EnsureDirectory,
    OpenDirectory,
    RandomName,
    SourceLock,
    SourceIdentity,
}

#[derive(Debug)]
pub(crate) enum QuarantinePublishFailure {
    Preparation {
        phase: QuarantinePreparePhase,
        source: std::io::Error,
        attempts_consumed: usize,
    },
    Move {
        quarantine_id: [u8; 16],
        quarantine_name: String,
        failure: MoveFailure,
        attempts_consumed: usize,
    },
    CollisionExhausted {
        attempts: usize,
        last_quarantine_id: [u8; 16],
        last_quarantine_name: String,
    },
    BudgetExhausted {
        attempts: usize,
        last_quarantine_id: [u8; 16],
        last_quarantine_name: String,
    },
}

impl QuarantinePublishFailure {
    pub(crate) fn attempts_consumed(&self) -> usize {
        match self {
            Self::Preparation {
                attempts_consumed, ..
            }
            | Self::Move {
                attempts_consumed, ..
            } => *attempts_consumed,
            Self::CollisionExhausted { attempts, .. } | Self::BudgetExhausted { attempts, .. } => {
                *attempts
            }
        }
    }
}

impl std::fmt::Display for QuarantinePublishFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Preparation { phase, source, .. } => {
                write!(
                    formatter,
                    "quarantine not committed at phase={phase:?}: {source}"
                )
            }
            Self::Move {
                quarantine_id,
                quarantine_name,
                failure,
                ..
            } => {
                let identity = steadq_names::hex_encode(quarantine_id);
                match failure {
                    MoveFailure::NotCommitted { phase, source } => write!(
                        formatter,
                        "quarantine not committed id={identity} name={quarantine_name} phase={phase:?}: {source}"
                    ),
                    MoveFailure::OutcomeUnknown { phase, source } => write!(
                        formatter,
                        "quarantine outcome unknown id={identity} name={quarantine_name} phase={phase:?}: {source}"
                    ),
                    MoveFailure::AlreadyExists => write!(
                        formatter,
                        "quarantine destination collision id={identity} name={quarantine_name}"
                    ),
                    MoveFailure::SourceMissing => write!(
                        formatter,
                        "quarantine source missing id={identity} name={quarantine_name}"
                    ),
                }
            }
            Self::CollisionExhausted {
                attempts,
                last_quarantine_id,
                last_quarantine_name,
            } => write!(
                formatter,
                "quarantine destination collision after {attempts} attempts last_id={} last_name={last_quarantine_name}",
                steadq_names::hex_encode(last_quarantine_id)
            ),
            Self::BudgetExhausted {
                attempts,
                last_quarantine_id,
                last_quarantine_name,
            } => write!(
                formatter,
                "quarantine retry budget exhausted after {attempts} attempts last_id={} last_name={last_quarantine_name}",
                steadq_names::hex_encode(last_quarantine_id)
            ),
        }
    }
}

impl std::error::Error for QuarantinePublishFailure {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct QuarantinePublication {
    pub(crate) quarantine_id: [u8; 16],
    pub(crate) quarantine_name: String,
    pub(crate) attempts_consumed: usize,
}

/// Fsck options.
#[derive(Clone, Debug)]
pub struct FsckOptions {
    pub mode: FsckMode,
    pub depth: FsckDepth,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsckMode {
    Check,
    Repair,
}

/// Fsck depth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsckDepth {
    /// Validate filename grammar, file type, link count, header decode,
    /// header/filename consistency, envelope digest, file size, name tag,
    /// and shard placement.
    Structural,
    /// Also hash and verify payload digests.
    Deep,
}

impl Default for FsckOptions {
    fn default() -> Self {
        FsckOptions {
            mode: FsckMode::Check,
            depth: FsckDepth::Structural,
        }
    }
}

/// A corruption finding from fsck.
#[derive(Clone, Debug)]
pub struct CorruptionFinding {
    pub relative_path: String,
    pub finding_type: String,
    pub severity: FindingSeverity,
    pub details: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingSeverity {
    Warning,
    Error,
}

/// Fsck report.
#[derive(Clone, Debug, Default)]
pub struct FsckReport {
    pub total_objects: u64,
    pub structurally_verified: u64,
    pub payloads_deep_verified: u64,
    pub findings: Vec<CorruptionFinding>,
    pub quarantined: Vec<[u8; 16]>,
}

fn fsck_protocol_name<'a>(
    parent: &str,
    entry: &'a fs::DirEntryName,
    report: &mut FsckReport,
) -> Option<&'a str> {
    let Some(name) = entry.as_ascii_str() else {
        let raw_name = steadq_names::hex_encode(entry.as_bytes());
        report.findings.push(CorruptionFinding {
            relative_path: format!("{parent}/<bytes:{raw_name}>"),
            finding_type: "invalid_name_encoding".into(),
            severity: FindingSeverity::Error,
            details: format!("directory entry name is not ASCII; raw_name_hex={raw_name}"),
        });
        return None;
    };
    Some(name)
}

impl Queue {
    /// Run fsck on the queue.
    pub fn fsck(&self, opts: &FsckOptions) -> FsckReport {
        let mut report = FsckReport::default();

        // Check ready shards
        self.fsck_state_dir("ready", opts, &mut report);
        // Check leased
        self.fsck_leased_dirs(opts, &mut report);
        // Check delayed
        self.fsck_state_dir("delayed", opts, &mut report);
        // Check dead
        self.fsck_state_dir("dead", opts, &mut report);
        // Check receipts
        self.fsck_state_dir("receipts", opts, &mut report);

        report
    }

    fn fsck_state_dir(&self, state_name: &str, opts: &FsckOptions, report: &mut FsckReport) {
        let root_fd = self.root_fd();
        let state_fd = match fs::open_directory(root_fd, state_name) {
            Ok(fd) => fd,
            Err(_) => return,
        };

        let top_entries = match fs::read_dir_entries(state_fd.as_fd()) {
            Ok(e) => e,
            Err(_) => return,
        };

        for raw_entry in &top_entries {
            let Some(entry) = fsck_protocol_name(state_name, raw_entry, report) else {
                continue;
            };
            let sub_fd = match fs::open_directory(state_fd.as_fd(), entry) {
                Ok(fd) => fd,
                Err(_) => continue,
            };

            let sub_entries = match fs::read_dir_entries(sub_fd.as_fd()) {
                Ok(e) => e,
                Err(_) => continue,
            };

            let sub_parent = format!("{state_name}/{entry}");
            for raw_sub_entry in &sub_entries {
                let Some(sub_entry) = fsck_protocol_name(&sub_parent, raw_sub_entry, report) else {
                    continue;
                };
                if sub_entry.ends_with(".sqj") || sub_entry.ends_with(".rct") {
                    // Carry full root-relative path
                    report.total_objects += 1;
                    let full_path = format!("{state_name}/{entry}/{sub_entry}");
                    self.fsck_file(
                        sub_fd.as_fd(),
                        state_name,
                        &full_path,
                        sub_entry,
                        opts,
                        report,
                    );
                } else {
                    // Another directory level (shard under bucket) or unexpected file.
                    let shard_fd = match fs::open_directory(sub_fd.as_fd(), sub_entry) {
                        Ok(fd) => fd,
                        Err(_) => {
                            report.findings.push(CorruptionFinding {
                                relative_path: format!("{state_name}/{entry}/{sub_entry}"),
                                finding_type: "unexpected_entry".into(),
                                severity: FindingSeverity::Warning,
                                details: format!(
                                    "unrecognized entry in state directory: {sub_entry}"
                                ),
                            });
                            continue;
                        }
                    };
                    let files = match fs::read_dir_entries(shard_fd.as_fd()) {
                        Ok(e) => e,
                        Err(_) => continue,
                    };
                    let shard_parent = format!("{sub_parent}/{sub_entry}");
                    for raw_file in &files {
                        let Some(file) = fsck_protocol_name(&shard_parent, raw_file, report) else {
                            continue;
                        };
                        if file.ends_with(".sqj") || file.ends_with(".rct") {
                            report.total_objects += 1;
                            let full_path = format!("{state_name}/{entry}/{sub_entry}/{file}");
                            self.fsck_file(
                                shard_fd.as_fd(),
                                state_name,
                                &full_path,
                                file,
                                opts,
                                report,
                            );
                        } else {
                            report.findings.push(CorruptionFinding {
                                relative_path: format!("{state_name}/{entry}/{sub_entry}/{file}"),
                                finding_type: "unexpected_entry".into(),
                                severity: FindingSeverity::Warning,
                                details: format!("unrecognized file in shard directory: {file}"),
                            });
                        }
                    }
                }
            }
        }
    }

    fn fsck_leased_dirs(&self, opts: &FsckOptions, report: &mut FsckReport) {
        let root_fd = self.root_fd();
        let leased_fd = match fs::open_directory(root_fd, "leased") {
            Ok(fd) => fd,
            Err(_) => return,
        };

        let boot_dirs = match fs::read_dir_entries(leased_fd.as_fd()) {
            Ok(e) => e,
            Err(_) => return,
        };

        for raw_boot_dir in &boot_dirs {
            let Some(boot_dir) = fsck_protocol_name("leased", raw_boot_dir, report) else {
                continue;
            };
            let boot_fd = match fs::open_directory(leased_fd.as_fd(), boot_dir) {
                Ok(fd) => fd,
                Err(_) => {
                    report.findings.push(CorruptionFinding {
                        relative_path: format!("leased/{boot_dir}"),
                        finding_type: "unexpected_entry".into(),
                        severity: FindingSeverity::Warning,
                        details: format!("non-directory entry in leased: {boot_dir}"),
                    });
                    continue;
                }
            };
            let bucket_dirs = match fs::read_dir_entries(boot_fd.as_fd()) {
                Ok(e) => e,
                Err(_) => continue,
            };
            let boot_parent = format!("leased/{boot_dir}");
            for raw_bucket_dir in &bucket_dirs {
                let Some(bucket_dir) = fsck_protocol_name(&boot_parent, raw_bucket_dir, report)
                else {
                    continue;
                };
                let bucket_fd = match fs::open_directory(boot_fd.as_fd(), bucket_dir) {
                    Ok(fd) => fd,
                    Err(_) => {
                        report.findings.push(CorruptionFinding {
                            relative_path: format!("leased/{boot_dir}/{bucket_dir}"),
                            finding_type: "unexpected_entry".into(),
                            severity: FindingSeverity::Warning,
                            details: format!(
                                "non-directory entry in leased boot dir: {bucket_dir}"
                            ),
                        });
                        continue;
                    }
                };
                let shard_dirs = match fs::read_dir_entries(bucket_fd.as_fd()) {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                let bucket_parent = format!("{boot_parent}/{bucket_dir}");
                for raw_shard_dir in &shard_dirs {
                    let Some(shard_dir) = fsck_protocol_name(&bucket_parent, raw_shard_dir, report)
                    else {
                        continue;
                    };
                    let shard_fd = match fs::open_directory(bucket_fd.as_fd(), shard_dir) {
                        Ok(fd) => fd,
                        Err(_) => {
                            report.findings.push(CorruptionFinding {
                                relative_path: format!("{bucket_parent}/{shard_dir}"),
                                finding_type: "unexpected_entry".into(),
                                severity: FindingSeverity::Warning,
                                details: format!(
                                    "non-directory entry in leased bucket: {shard_dir}"
                                ),
                            });
                            continue;
                        }
                    };
                    let files = match fs::read_dir_entries(shard_fd.as_fd()) {
                        Ok(e) => e,
                        Err(_) => continue,
                    };
                    let shard_parent = format!("{bucket_parent}/{shard_dir}");
                    for raw_file in &files {
                        let Some(file) = fsck_protocol_name(&shard_parent, raw_file, report) else {
                            continue;
                        };
                        if file.ends_with(".sqj") {
                            report.total_objects += 1;
                            let full_path =
                                format!("leased/{boot_dir}/{bucket_dir}/{shard_dir}/{file}");
                            self.fsck_file(
                                shard_fd.as_fd(),
                                "leased",
                                &full_path,
                                file,
                                opts,
                                report,
                            );
                        } else {
                            report.findings.push(CorruptionFinding {
                                relative_path: format!(
                                    "leased/{boot_dir}/{bucket_dir}/{shard_dir}/{file}"
                                ),
                                finding_type: "unexpected_entry".into(),
                                severity: FindingSeverity::Warning,
                                details: format!("unrecognized file in leased shard: {file}"),
                            });
                        }
                    }
                }
            }
        }
    }

    /// Deep structural verification of a single object.
    /// Validates filename grammar, file type, link count, header decode,
    /// header/filename consistency, envelope digest, file size, name tag,
    /// and shard placement. In Deep mode, also hashes the payload.
    /// In Repair mode, quarantines objects that fail any structural check.
    #[allow(clippy::too_many_arguments)]
    fn fsck_file(
        &self,
        shard_fd: BorrowedFd<'_>,
        state_name: &str,
        full_path: &str,
        filename: &str,
        opts: &FsckOptions,
        report: &mut FsckReport,
    ) {
        let queue_id = self.format.queue_id();

        // Parse the filename using the state-appropriate parser.
        // Extract job_id, generation, attempt, max_attempts, tag from the parsed result.
        let parsed = match state_name {
            "ready" => match steadq_names::parse_ready(filename) {
                Ok(p) => Some((p.common, p.tag, None)),
                Err(_) => match steadq_names::parse_leased(filename) {
                    Ok(p) => Some((p.common, p.tag, Some(p.token))),
                    Err(_) => None,
                },
            },
            "leased" => match steadq_names::parse_leased(filename) {
                Ok(p) => Some((p.common, p.tag, Some(p.token))),
                Err(_) => None,
            },
            "delayed" => match steadq_names::parse_delayed(filename) {
                Ok(p) => Some((p.common, p.tag, None)),
                Err(_) => None,
            },
            "dead" => match steadq_names::parse_dead(filename) {
                Ok(p) => Some((p.common, p.tag, None)),
                Err(_) => None,
            },
            "receipts" => match steadq_names::parse_receipt(filename) {
                Ok(p) => Some((p.common, p.tag, Some(p.token))),
                Err(_) => None,
            },
            _ => None,
        };

        let (common, parsed_tag, token) = match parsed {
            Some(v) => v,
            None => {
                report.findings.push(CorruptionFinding {
                    relative_path: full_path.to_string(),
                    finding_type: "filename_parse_failed".into(),
                    severity: FindingSeverity::Error,
                    details: format!("filename does not match {state_name} state grammar"),
                });
                if opts.mode == FsckMode::Repair {
                    self.repair_quarantine_candidate(
                        state_name,
                        shard_fd,
                        filename,
                        full_path,
                        crate::QuarantineReason::FilenameParseFailed,
                        report,
                    );
                }
                return;
            }
        };

        // Stat the file.
        let stat = match fs::fstatat(shard_fd, filename) {
            Ok(s) => s,
            Err(_) => {
                report.findings.push(CorruptionFinding {
                    relative_path: full_path.to_string(),
                    finding_type: "stat_failed".into(),
                    severity: FindingSeverity::Error,
                    details: "cannot stat file".into(),
                });
                return;
            }
        };

        // Regular file check.
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
            report.findings.push(CorruptionFinding {
                relative_path: full_path.to_string(),
                finding_type: "non_regular_file".into(),
                severity: FindingSeverity::Error,
                details: "file is not a regular file".into(),
            });
            if opts.mode == FsckMode::Repair {
                self.repair_quarantine_candidate(
                    state_name,
                    shard_fd,
                    filename,
                    full_path,
                    crate::QuarantineReason::NonRegularFile,
                    report,
                );
            }
            return;
        }

        // Hard link check.
        if stat.st_nlink != 1 {
            report.findings.push(CorruptionFinding {
                relative_path: full_path.to_string(),
                finding_type: "unexpected_hard_link".into(),
                severity: FindingSeverity::Error,
                details: format!("link count is {} (expected 1)", stat.st_nlink),
            });
            if opts.mode == FsckMode::Repair {
                self.repair_quarantine_candidate(
                    state_name,
                    shard_fd,
                    filename,
                    full_path,
                    crate::QuarantineReason::UnexpectedHardLink,
                    report,
                );
            }
            return;
        }

        // Read and decode the header.
        // Receipts may be compact (128 bytes with RECEIPT_MAGIC).
        let open_flags = if state_name == "receipts" && opts.mode == FsckMode::Repair {
            crate::queue::verified::receipt_write_open_flags()
        } else {
            crate::queue::verified::receipt_read_open_flags()
        };
        let file_fd = match fs::openat(shard_fd, filename, open_flags, 0) {
            Ok(f) => f,
            Err(_) => {
                report.findings.push(CorruptionFinding {
                    relative_path: full_path.to_string(),
                    finding_type: "open_failed".into(),
                    severity: FindingSeverity::Error,
                    details: "cannot open file for reading".into(),
                });
                return;
            }
        };

        if state_name == "receipts" {
            let path_parts: Vec<&str> = full_path.split('/').collect();
            let receipt_result = match path_parts.as_slice() {
                ["receipts", bucket, shard, _] => crate::queue::verified::verify_receipt_on_fd(
                    file_fd.as_fd(),
                    crate::queue::verified::ReceiptContext {
                        queue_id,
                        shard_count: self.format.shard_count(),
                        terminal_bucket_width_ns: self.format.terminal_bucket_width_ns(),
                        max_payload_length: self.format.max_payload_length(),
                        bucket,
                        shard,
                        filename,
                    },
                    None,
                ),
                _ => Err(crate::queue::verified::VerificationError::Corrupt(
                    "receipt path has invalid depth".into(),
                )),
            };

            match receipt_result {
                Ok(receipt) => {
                    report.structurally_verified += 1;
                    if matches!(
                        receipt.kind,
                        crate::queue::verified::VerifiedReceiptKind::Full(_)
                    ) {
                        report.payloads_deep_verified += 1;
                    }
                }
                Err(error) => {
                    let reason = if matches!(
                        error,
                        crate::queue::verified::VerificationError::PayloadCorrupt
                    ) {
                        crate::QuarantineReason::PayloadCorrupt
                    } else {
                        crate::QuarantineReason::EnvelopeCorrupt
                    };
                    report.findings.push(CorruptionFinding {
                        relative_path: full_path.to_string(),
                        finding_type: "receipt_verification_failed".into(),
                        severity: FindingSeverity::Error,
                        details: error.to_string(),
                    });
                    if opts.mode == FsckMode::Repair {
                        if let Err(repair_error) = self.quarantine_opened_object(
                            shard_fd, filename, full_path, &file_fd, reason, report,
                        ) {
                            report.findings.push(CorruptionFinding {
                                relative_path: full_path.to_string(),
                                finding_type: "quarantine_failed".into(),
                                severity: FindingSeverity::Error,
                                details: repair_error.to_string(),
                            });
                        }
                    }
                }
            }
            return;
        }

        // Publication fsyncs file data before linking the name, so a
        // zero-length named object is residue of an interrupted publication:
        // it can never represent a committed job. Quarantine in Repair mode.
        if fs::fstat(file_fd.as_fd())
            .map(|st| st.st_size == 0)
            .unwrap_or(false)
        {
            report.findings.push(CorruptionFinding {
                relative_path: full_path.to_string(),
                finding_type: "zero_length_publication_residue".into(),
                severity: FindingSeverity::Warning,
                details: "name published without durable content".into(),
            });
            if opts.mode == FsckMode::Repair {
                self.quarantine_object_or_record(
                    shard_fd,
                    filename,
                    full_path,
                    crate::QuarantineReason::EnvelopeCorrupt,
                    report,
                );
            }
            return;
        }

        let mut header_buf = [0u8; 128];
        if let Err(read_error) = fs::pread_exact(file_fd.as_fd(), &mut header_buf, 0) {
            let file_size = fs::fstat(file_fd.as_fd())
                .map(|st| st.st_size.to_string())
                .unwrap_or_else(|e| format!("fstat error {e}"));
            report.findings.push(CorruptionFinding {
                relative_path: full_path.to_string(),
                finding_type: "header_read_failed".into(),
                severity: FindingSeverity::Error,
                details: format!(
                    "cannot read 128-byte header: size={file_size}, error={read_error}"
                ),
            });
            if opts.mode == FsckMode::Repair {
                self.quarantine_object_or_record(
                    shard_fd,
                    filename,
                    full_path,
                    crate::QuarantineReason::EnvelopeCorrupt,
                    report,
                );
            }
            return;
        }

        // Full header decode for .sqj files.
        let header = match steadq_format::FixedHeader::decode(&header_buf) {
            Ok(h) => h,
            Err(e) => {
                report.findings.push(CorruptionFinding {
                    relative_path: full_path.to_string(),
                    finding_type: "header_decode_failed".into(),
                    severity: FindingSeverity::Error,
                    details: format!("header decode error: {e}"),
                });
                if opts.mode == FsckMode::Repair {
                    self.quarantine_object_or_record(
                        shard_fd,
                        filename,
                        full_path,
                        crate::QuarantineReason::EnvelopeCorrupt,
                        report,
                    );
                }
                return;
            }
        };

        // Verify header job_id matches filename.
        if header.job_id != common.job_id {
            report.findings.push(CorruptionFinding {
                relative_path: full_path.to_string(),
                finding_type: "header_job_id_mismatch".into(),
                severity: FindingSeverity::Error,
                details: "header job_id does not match filename".into(),
            });
            if opts.mode == FsckMode::Repair {
                self.quarantine_object_or_record(
                    shard_fd,
                    filename,
                    full_path,
                    crate::QuarantineReason::FilenameHeaderMismatch,
                    report,
                );
            }
            return;
        }

        // Verify header maximum_attempts matches filename.
        if header.maximum_attempts != common.maximum_attempts {
            report.findings.push(CorruptionFinding {
                relative_path: full_path.to_string(),
                finding_type: "header_max_attempts_mismatch".into(),
                severity: FindingSeverity::Error,
                details: "header maximum_attempts does not match filename".into(),
            });
            if opts.mode == FsckMode::Repair {
                self.quarantine_object_or_record(
                    shard_fd,
                    filename,
                    full_path,
                    crate::QuarantineReason::FilenameHeaderMismatch,
                    report,
                );
            }
            return;
        }

        // Read extension and verify envelope digest.
        let ext_len = header.extension_header_length as usize;
        if ext_len > 65536 {
            report.findings.push(CorruptionFinding {
                relative_path: full_path.to_string(),
                finding_type: "extension_too_large".into(),
                severity: FindingSeverity::Error,
                details: format!("extension header length {ext_len} exceeds 65536"),
            });
            if opts.mode == FsckMode::Repair {
                self.quarantine_object_or_record(
                    shard_fd,
                    filename,
                    full_path,
                    crate::QuarantineReason::EnvelopeCorrupt,
                    report,
                );
            }
            return;
        }
        let mut ext_buf = vec![0u8; ext_len];
        if ext_len > 0 && fs::pread_exact(file_fd.as_fd(), &mut ext_buf, 128).is_err() {
            report.findings.push(CorruptionFinding {
                relative_path: full_path.to_string(),
                finding_type: "extension_read_failed".into(),
                severity: FindingSeverity::Error,
                details: "cannot read extension header".into(),
            });
            if opts.mode == FsckMode::Repair {
                self.quarantine_object_or_record(
                    shard_fd,
                    filename,
                    full_path,
                    crate::QuarantineReason::EnvelopeCorrupt,
                    report,
                );
            }
            return;
        }
        if !crate::queue::verified::is_envelope_digest_valid(&header, &ext_buf) {
            report.findings.push(CorruptionFinding {
                relative_path: full_path.to_string(),
                finding_type: "envelope_digest_mismatch".into(),
                severity: FindingSeverity::Error,
                details: "envelope digest does not match header".into(),
            });
            if opts.mode == FsckMode::Repair {
                self.quarantine_object_or_record(
                    shard_fd,
                    filename,
                    full_path,
                    crate::QuarantineReason::EnvelopeCorrupt,
                    report,
                );
            }
            return;
        }

        // Verify file size matches expected.
        if stat.st_size < 0 {
            report.findings.push(CorruptionFinding {
                relative_path: full_path.to_string(),
                finding_type: "negative_file_size".into(),
                severity: FindingSeverity::Error,
                details: format!("negative file size: {}", stat.st_size),
            });
            return;
        }
        let expected_size = 128u64
            .checked_add(ext_len as u64)
            .and_then(|s| s.checked_add(header.payload_length))
            .unwrap_or(u64::MAX);
        if stat.st_size as u64 != expected_size {
            report.findings.push(CorruptionFinding {
                relative_path: full_path.to_string(),
                finding_type: "file_size_mismatch".into(),
                severity: FindingSeverity::Error,
                details: format!(
                    "size mismatch: expected {expected_size}, got {}",
                    stat.st_size
                ),
            });
            if opts.mode == FsckMode::Repair {
                self.quarantine_object_or_record(
                    shard_fd,
                    filename,
                    full_path,
                    crate::QuarantineReason::EnvelopeCorrupt,
                    report,
                );
            }
            return;
        }

        // Verify payload limit.
        if header.payload_length > self.format.max_payload_length() {
            report.findings.push(CorruptionFinding {
                relative_path: full_path.to_string(),
                finding_type: "payload_exceeds_limit".into(),
                severity: FindingSeverity::Error,
                details: format!(
                    "payload length {} exceeds queue limit {}",
                    header.payload_length,
                    self.format.max_payload_length()
                ),
            });
            if opts.mode == FsckMode::Repair {
                self.quarantine_object_or_record(
                    shard_fd,
                    filename,
                    full_path,
                    crate::QuarantineReason::EnvelopeCorrupt,
                    report,
                );
            }
            return;
        }

        // Verify name tag using path-derived context.
        let path_parts: Vec<&str> = full_path.split('/').collect();
        let tag_ok = self.fsck_verify_name_tag(
            state_name,
            &path_parts,
            &common,
            parsed_tag,
            token,
            queue_id,
        );
        if !tag_ok {
            report.findings.push(CorruptionFinding {
                relative_path: full_path.to_string(),
                finding_type: "name_tag_mismatch".into(),
                severity: FindingSeverity::Error,
                details: "name tag does not match computed tag for this context".into(),
            });
            if opts.mode == FsckMode::Repair {
                self.quarantine_object_or_record(
                    shard_fd,
                    filename,
                    full_path,
                    crate::QuarantineReason::FilenameTagFailed,
                    report,
                );
            }
            return;
        }

        // Verify shard placement.
        let computed_shard =
            steadq_names::compute_shard(queue_id, &common.job_id, self.format.shard_count());
        let shard_hex_in_path = self.fsck_extract_shard_hex(state_name, &path_parts);
        if let Some(shard_hex) = shard_hex_in_path {
            if let Some(path_shard) = steadq_names::shard_from_hex(shard_hex) {
                if path_shard != computed_shard {
                    report.findings.push(CorruptionFinding {
                        relative_path: full_path.to_string(),
                        finding_type: "shard_placement_mismatch".into(),
                        severity: FindingSeverity::Error,
                        details: format!(
                            "shard {path_shard} in path does not match computed shard {computed_shard}"
                        ),
                    });
                    if opts.mode == FsckMode::Repair {
                        self.quarantine_object_or_record(
                            shard_fd,
                            filename,
                            full_path,
                            crate::QuarantineReason::FilenameTagFailed,
                            report,
                        );
                    }
                    return;
                }
            }
        }

        report.structurally_verified += 1;

        // Deep verification - hash the payload.
        if opts.depth == FsckDepth::Deep && state_name != "receipts" {
            let payload_offset = (128 + ext_len) as u64;
            let mut hasher = sha2::Sha256::new();
            let mut buf = vec![0u8; 65536];
            let mut offset = payload_offset;
            let mut remaining = header.payload_length as usize;
            let mut read_ok = true;
            while remaining > 0 {
                let to_read = remaining.min(buf.len());
                match fs::pread(file_fd.as_fd(), &mut buf[..to_read], offset) {
                    Ok(n) if n > 0 => {
                        hasher.update(&buf[..n]);
                        offset += n as u64;
                        remaining -= n;
                    }
                    _ => {
                        read_ok = false;
                        break;
                    }
                }
            }
            if !read_ok {
                report.findings.push(CorruptionFinding {
                    relative_path: full_path.to_string(),
                    finding_type: "payload_read_failed".into(),
                    severity: FindingSeverity::Error,
                    details: "cannot read payload for deep verification".into(),
                });
                return;
            }
            let computed: [u8; 32] = hasher.finalize().into();
            if computed != header.payload_digest {
                report.findings.push(CorruptionFinding {
                    relative_path: full_path.to_string(),
                    finding_type: "payload_digest_mismatch".into(),
                    severity: FindingSeverity::Error,
                    details: "payload digest does not match header".into(),
                });
                if opts.mode == FsckMode::Repair {
                    self.quarantine_object_or_record(
                        shard_fd,
                        filename,
                        full_path,
                        crate::QuarantineReason::PayloadCorrupt,
                        report,
                    );
                }
                return;
            }
            report.payloads_deep_verified += 1;
        }
    }

    /// Verify the name tag by reconstructing the canonical context
    /// from the path components and the parsed filename fields.
    fn fsck_verify_name_tag(
        &self,
        state_name: &str,
        path_parts: &[&str],
        common: &steadq_names::CommonFields,
        parsed_tag: [u8; 8],
        _token: Option<[u8; 16]>,
        queue_id: &[u8; 16],
    ) -> bool {
        // Use canonical authentication from steadq-names instead of
        // reconstructing tag contexts independently. Wrong path shapes fail
        // closed (return false) instead of returning true.
        match state_name {
            "ready" => {
                if path_parts.len() != 3 {
                    return false;
                }
                let shard_hex = path_parts[1];
                let filename = path_parts[2];
                if let Ok(parsed) = steadq_names::parse_leased(filename) {
                    let boot = steadq_names::format_boot_id(&parsed.boot_id);
                    let Some(bucket) = steadq_math::lease_bucket(
                        parsed.boottime_deadline_ns,
                        self.format.lease_bucket_width_ns(),
                    ) else {
                        return false;
                    };
                    return parsed.authenticate_tag(
                        queue_id,
                        &boot,
                        &steadq_names::bucket_hex(bucket),
                        shard_hex,
                    );
                }
                let name = steadq_names::ReadyName {
                    common: common.clone(),
                    tag: parsed_tag,
                };
                name.authenticate_tag(queue_id, shard_hex)
            }
            "leased" => {
                if path_parts.len() != 5 {
                    return false;
                }
                let boot = path_parts[1];
                let bucket = path_parts[2];
                let shard_hex = path_parts[3];
                let filename = path_parts[4];
                match steadq_names::parse_leased(filename) {
                    Ok(p) => p.authenticate_tag(queue_id, boot, bucket, shard_hex),
                    Err(_) => false,
                }
            }
            "delayed" => {
                if path_parts.len() != 4 {
                    return false;
                }
                let bucket = path_parts[1];
                let shard_hex = path_parts[2];
                let filename = path_parts[3];
                match steadq_names::parse_delayed(filename) {
                    Ok(p) => p.authenticate_tag(queue_id, bucket, shard_hex),
                    Err(_) => false,
                }
            }
            "dead" => {
                if path_parts.len() != 4 {
                    return false;
                }
                let bucket = path_parts[1];
                let shard_hex = path_parts[2];
                let filename = path_parts[3];
                match steadq_names::parse_dead(filename) {
                    Ok(p) => p.authenticate_tag(queue_id, bucket, shard_hex),
                    Err(_) => false,
                }
            }
            "receipts" => {
                if path_parts.len() != 4 {
                    return false;
                }
                let bucket = path_parts[1];
                let shard_hex = path_parts[2];
                let filename = path_parts[3];
                match steadq_names::parse_receipt(filename) {
                    Ok(p) => p.authenticate_tag(queue_id, bucket, shard_hex),
                    Err(_) => false,
                }
            }
            _ => false,
        }
    }

    fn fsck_extract_shard_hex<'a>(
        &self,
        state_name: &str,
        path_parts: &[&'a str],
    ) -> Option<&'a str> {
        match state_name {
            "ready" if path_parts.len() == 3 => Some(path_parts[1]),
            "leased" if path_parts.len() == 5 => Some(path_parts[3]),
            "delayed" | "dead" | "receipts" if path_parts.len() == 4 => Some(path_parts[2]),
            _ => None,
        }
    }

    pub(crate) fn publish_quarantine_object(
        &self,
        src_dir_fd: BorrowedFd<'_>,
        filename: &str,
        reason: crate::QuarantineReason,
    ) -> Result<QuarantinePublication, QuarantinePublishFailure> {
        self.publish_quarantine_object_with_ids(
            src_dir_fd,
            filename,
            reason,
            QUARANTINE_NAME_ATTEMPTS,
            fs::random_128bit,
        )
    }

    pub(crate) fn publish_quarantine_object_with_ids<F>(
        &self,
        src_dir_fd: BorrowedFd<'_>,
        filename: &str,
        reason: crate::QuarantineReason,
        max_move_attempts: usize,
        mut next_id: F,
    ) -> Result<QuarantinePublication, QuarantinePublishFailure>
    where
        F: FnMut() -> std::io::Result<[u8; 16]>,
    {
        let attempt_limit = max_move_attempts.min(QUARANTINE_NAME_ATTEMPTS);
        if attempt_limit == 0 {
            return Err(QuarantinePublishFailure::Preparation {
                phase: QuarantinePreparePhase::AttemptBudget,
                source: std::io::Error::other("no quarantine move attempt budget remains"),
                attempts_consumed: 0,
            });
        }
        self.ensure_dir("quarantine")
            .map_err(|error| QuarantinePublishFailure::Preparation {
                phase: QuarantinePreparePhase::EnsureDirectory,
                source: error,
                attempts_consumed: 0,
            })?;
        let quarantine_dir =
            crate::queue::open_relative(self.root_fd(), "quarantine").map_err(|error| {
                QuarantinePublishFailure::Preparation {
                    phase: QuarantinePreparePhase::OpenDirectory,
                    source: error,
                    attempts_consumed: 0,
                }
            })?;

        for attempts in 1..=attempt_limit {
            let quarantine_id =
                next_id().map_err(|error| QuarantinePublishFailure::Preparation {
                    phase: QuarantinePreparePhase::RandomName,
                    source: error,
                    attempts_consumed: attempts - 1,
                })?;
            let quarantine_name = steadq_names::quarantine_filename(&quarantine_id, reason as u16);
            match move_verified_noreplace(
                src_dir_fd,
                filename,
                quarantine_dir.as_fd(),
                &quarantine_name,
            ) {
                Ok(()) => {
                    return Ok(QuarantinePublication {
                        quarantine_id,
                        quarantine_name,
                        attempts_consumed: attempts,
                    })
                }
                Err(failure) if quarantine_destination_collision(&failure) => {
                    if attempts == attempt_limit {
                        return if attempt_limit == QUARANTINE_NAME_ATTEMPTS {
                            Err(QuarantinePublishFailure::CollisionExhausted {
                                attempts,
                                last_quarantine_id: quarantine_id,
                                last_quarantine_name: quarantine_name,
                            })
                        } else {
                            Err(QuarantinePublishFailure::BudgetExhausted {
                                attempts,
                                last_quarantine_id: quarantine_id,
                                last_quarantine_name: quarantine_name,
                            })
                        };
                    }
                }
                Err(failure) => {
                    return Err(QuarantinePublishFailure::Move {
                        quarantine_id,
                        quarantine_name,
                        failure,
                        attempts_consumed: attempts,
                    })
                }
            }
        }
        unreachable!("quarantine attempt bound is nonzero")
    }

    /// Move a corrupt object to quarantine via durable no-overwrite transition.
    fn quarantine_object(
        &self,
        src_dir_fd: BorrowedFd<'_>,
        filename: &str,
        full_path: &str,
        reason: crate::QuarantineReason,
        report: &mut FsckReport,
    ) -> Result<(), QuarantinePublishFailure> {
        let publication = self.publish_quarantine_object(src_dir_fd, filename, reason)?;
        report.quarantined.push(publication.quarantine_id);
        report.findings.push(CorruptionFinding {
            relative_path: full_path.to_string(),
            finding_type: "quarantined".into(),
            severity: FindingSeverity::Warning,
            details: format!(
                "moved to quarantine id={} name={}",
                steadq_names::hex_encode(&publication.quarantine_id),
                publication.quarantine_name
            ),
        });
        Ok(())
    }

    fn quarantine_object_or_record(
        &self,
        src_dir_fd: BorrowedFd<'_>,
        filename: &str,
        full_path: &str,
        reason: crate::QuarantineReason,
        report: &mut FsckReport,
    ) {
        if let Err(error) = self.quarantine_object(src_dir_fd, filename, full_path, reason, report)
        {
            report.findings.push(CorruptionFinding {
                relative_path: full_path.to_string(),
                finding_type: "quarantine_failed".into(),
                severity: FindingSeverity::Error,
                details: error.to_string(),
            });
        }
    }

    fn repair_quarantine_candidate(
        &self,
        state_name: &str,
        src_dir_fd: BorrowedFd<'_>,
        filename: &str,
        full_path: &str,
        reason: crate::QuarantineReason,
        report: &mut FsckReport,
    ) {
        let result = if state_name == "receipts" {
            match fs::openat(
                src_dir_fd,
                filename,
                crate::queue::verified::receipt_write_open_flags(),
                0,
            ) {
                Ok(opened) => self.quarantine_opened_object(
                    src_dir_fd, filename, full_path, &opened, reason, report,
                ),
                Err(error) => Err(QuarantinePublishFailure::Preparation {
                    phase: QuarantinePreparePhase::SourceIdentity,
                    source: error,
                    attempts_consumed: 0,
                }),
            }
        } else {
            self.quarantine_object(src_dir_fd, filename, full_path, reason, report)
        };

        if let Err(error) = result {
            report.findings.push(CorruptionFinding {
                relative_path: full_path.to_string(),
                finding_type: "quarantine_failed".into(),
                severity: FindingSeverity::Error,
                details: error.to_string(),
            });
        }
    }

    fn quarantine_opened_object(
        &self,
        src_dir_fd: BorrowedFd<'_>,
        filename: &str,
        full_path: &str,
        opened: &std::os::fd::OwnedFd,
        reason: crate::QuarantineReason,
        report: &mut FsckReport,
    ) -> Result<(), QuarantinePublishFailure> {
        let locked = steadq_fs_linux::try_ofd_write_lock(opened.as_fd()).map_err(|error| {
            QuarantinePublishFailure::Preparation {
                phase: QuarantinePreparePhase::SourceLock,
                source: error,
                attempts_consumed: 0,
            }
        })?;
        if !locked {
            return Err(QuarantinePublishFailure::Preparation {
                phase: QuarantinePreparePhase::SourceLock,
                source: std::io::Error::other("receipt is busy"),
                attempts_consumed: 0,
            });
        }
        let opened_stat = steadq_fs_linux::fstat(opened.as_fd()).map_err(|error| {
            QuarantinePublishFailure::Preparation {
                phase: QuarantinePreparePhase::SourceIdentity,
                source: error,
                attempts_consumed: 0,
            }
        })?;
        let current_stat = steadq_fs_linux::fstatat(src_dir_fd, filename).map_err(|error| {
            QuarantinePublishFailure::Preparation {
                phase: QuarantinePreparePhase::SourceIdentity,
                source: error,
                attempts_consumed: 0,
            }
        })?;
        if !crate::queue::verified::receipt_path_identity_matches(
            &current_stat,
            opened_stat.st_dev,
            opened_stat.st_ino,
        ) {
            return Err(QuarantinePublishFailure::Preparation {
                phase: QuarantinePreparePhase::SourceIdentity,
                source: std::io::Error::other("receipt path no longer names the verified inode"),
                attempts_consumed: 0,
            });
        }

        self.quarantine_object(src_dir_fd, filename, full_path, reason, report)
    }

    /// List all quarantined objects under the queue root.
    ///
    /// Quarantine objects live as `quarantine/q{id}.x{reason}.raw` (flat).
    /// Nested layouts are also scanned for compatibility with older trees.
    pub fn list_quarantine(&self) -> Vec<QuarantineEntry> {
        let mut out = Vec::new();
        let root = &self.root_path;
        let qroot = root.join("quarantine");
        if !qroot.is_dir() {
            return out;
        }
        collect_quarantine_entries(&qroot, root, &mut out);
        out
    }

    /// Find a quarantined object by quarantine id.
    pub fn find_quarantine(&self, quarantine_id: &[u8; 16]) -> Option<QuarantineEntry> {
        self.list_quarantine()
            .into_iter()
            .find(|e| e.quarantine_id == *quarantine_id)
    }

    /// Remove a quarantined object by id. Returns true if a file was removed.
    pub fn remove_quarantine(&self, quarantine_id: &[u8; 16]) -> Result<bool, std::io::Error> {
        match self.find_quarantine(quarantine_id) {
            Some(entry) => {
                std::fs::remove_file(self.root_path.join(&entry.relative_path))?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Copy a quarantined object's raw bytes to `output`. Returns bytes written.
    pub fn export_quarantine(
        &self,
        quarantine_id: &[u8; 16],
        output: &std::path::Path,
    ) -> Result<u64, std::io::Error> {
        match self.find_quarantine(quarantine_id) {
            Some(entry) => {
                let n = std::fs::copy(self.root_path.join(&entry.relative_path), output)?;
                Ok(n)
            }
            None => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "quarantine object not found",
            )),
        }
    }
}

/// A quarantined object discovered under the queue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuarantineEntry {
    pub quarantine_id: [u8; 16],
    pub reason: u16,
    pub filename: String,
    pub relative_path: String,
}

fn collect_quarantine_entries(
    dir: &std::path::Path,
    root: &std::path::Path,
    out: &mut Vec<QuarantineEntry>,
) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_quarantine_entries(&path, root, out);
            continue;
        }
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if let Ok(parsed) = steadq_names::parse_quarantine(&name) {
            let Some(relative) = path
                .strip_prefix(root)
                .ok()
                .and_then(std::path::Path::to_str)
            else {
                continue;
            };
            out.push(QuarantineEntry {
                quarantine_id: parsed.quarantine_id,
                reason: parsed.reason,
                filename: name,
                relative_path: relative.to_string(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::queue::{CreateOptions, EnqueueInput, OpenOptions, Queue};
    use tempfile::TempDir;

    /// Pins the realtime clock before init so no delayed-bucket boundary can
    /// trigger a watermark advance that steals a count-based fault.
    fn init_test_queue(path: &std::path::Path) {
        fs::fault::pin_clock_realtime_ns(fs::clock_realtime_ns().unwrap());
        Queue::init(path, &CreateOptions::default()).unwrap();
    }

    fn open_test_queue(path: &std::path::Path) -> Queue {
        Queue::open(
            path,
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap()
    }

    fn queue_with_quarantine_candidate() -> (TempDir, Queue) {
        let tmp = TempDir::new().unwrap();
        init_test_queue(tmp.path());
        std::fs::write(tmp.path().join("candidate.raw"), b"candidate").unwrap();
        let queue = open_test_queue(tmp.path());
        (tmp, queue)
    }

    fn different_byte(original: u8) -> u8 {
        original ^ u8::MAX
    }

    #[test]
    fn corrupt_header_fixture_changes_every_byte_value() {
        for original in u8::MIN..=u8::MAX {
            assert_ne!(different_byte(original), original);
        }
    }

    #[test]
    fn quarantine_collision_and_attempt_boundaries_are_exact() {
        assert!(quarantine_destination_collision(
            &MoveFailure::AlreadyExists
        ));
        assert!(!quarantine_destination_collision(
            &MoveFailure::SourceMissing
        ));
        assert!(!quarantine_destination_collision(
            &MoveFailure::NotCommitted {
                phase: crate::queue::engine::MovePhase::Rename,
                source: std::io::Error::other("io"),
            }
        ));
        assert!(!quarantine_destination_collision(
            &MoveFailure::OutcomeUnknown {
                phase: crate::queue::engine::MovePhase::DestFsync,
                source: std::io::Error::other("io"),
            }
        ));
    }

    #[test]
    fn quarantine_publication_faults_reopen_and_replay() {
        for (fault, count, expected_phase, source_remains) in [
            ("mkdirat", 1, "prepare:EnsureDirectory", true),
            ("renameat2_noreplace", 1, "move:Rename", true),
            ("fsync_dir_fd", 1, "move:DestFsync", false),
            ("fsync_dir_fd", 2, "move:SourceFsync", false),
        ] {
            let (tmp, queue) = queue_with_quarantine_candidate();
            let quarantine_id = [count as u8; 16];
            let quarantine_name = steadq_names::quarantine_filename(
                &quarantine_id,
                crate::QuarantineReason::EnvelopeCorrupt as u16,
            );
            fs::fault::reset();
            fs::fault::inject_errno(fault, count, libc::EIO);
            let result = queue.publish_quarantine_object_with_ids(
                queue.root_fd(),
                "candidate.raw",
                crate::QuarantineReason::EnvelopeCorrupt,
                QUARANTINE_NAME_ATTEMPTS,
                || Ok(quarantine_id),
            );
            fs::fault::reset();

            let failure = result.unwrap_err();
            match expected_phase {
                "prepare:EnsureDirectory" => assert!(matches!(
                    failure,
                    QuarantinePublishFailure::Preparation {
                        phase: QuarantinePreparePhase::EnsureDirectory,
                        ..
                    }
                )),
                "move:Rename" => assert!(matches!(
                    failure,
                    QuarantinePublishFailure::Move {
                        failure: MoveFailure::NotCommitted {
                            phase: crate::queue::engine::MovePhase::Rename,
                            ..
                        },
                        ..
                    }
                )),
                "move:DestFsync" => assert!(matches!(
                    failure,
                    QuarantinePublishFailure::Move {
                        failure: MoveFailure::OutcomeUnknown {
                            phase: crate::queue::engine::MovePhase::DestFsync,
                            ..
                        },
                        ..
                    }
                )),
                "move:SourceFsync" => assert!(matches!(
                    failure,
                    QuarantinePublishFailure::Move {
                        failure: MoveFailure::OutcomeUnknown {
                            phase: crate::queue::engine::MovePhase::SourceFsync,
                            ..
                        },
                        ..
                    }
                )),
                other => panic!("unexpected expected phase {other}"),
            }
            assert_eq!(tmp.path().join("candidate.raw").exists(), source_remains);
            assert_eq!(
                tmp.path()
                    .join("quarantine")
                    .join(&quarantine_name)
                    .exists(),
                !source_remains
            );

            drop(queue);
            let reopened = open_test_queue(tmp.path());
            if source_remains {
                let publication = reopened
                    .publish_quarantine_object_with_ids(
                        reopened.root_fd(),
                        "candidate.raw",
                        crate::QuarantineReason::EnvelopeCorrupt,
                        QUARANTINE_NAME_ATTEMPTS,
                        || Ok(quarantine_id),
                    )
                    .unwrap();
                assert_eq!(publication.quarantine_id, quarantine_id);
                assert_eq!(publication.quarantine_name, quarantine_name);
            } else {
                assert_eq!(
                    std::fs::read(tmp.path().join("quarantine").join(&quarantine_name)).unwrap(),
                    b"candidate"
                );
                let replay_id = [0xf0; 16];
                assert!(matches!(
                    reopened.publish_quarantine_object_with_ids(
                        reopened.root_fd(),
                        "candidate.raw",
                        crate::QuarantineReason::EnvelopeCorrupt,
                        QUARANTINE_NAME_ATTEMPTS,
                        || Ok(replay_id)
                    ),
                    Err(QuarantinePublishFailure::Move {
                        failure: MoveFailure::SourceMissing,
                        ..
                    })
                ));
            }
        }
    }

    #[test]
    fn quarantine_random_name_failure_reopens_and_replays() {
        let (tmp, queue) = queue_with_quarantine_candidate();
        fs::fault::reset();
        fs::fault::inject_errno("get_random", 1, libc::EIO);
        let result = queue.publish_quarantine_object(
            queue.root_fd(),
            "candidate.raw",
            crate::QuarantineReason::EnvelopeCorrupt,
        );
        fs::fault::reset();
        assert!(matches!(
            result,
            Err(QuarantinePublishFailure::Preparation {
                phase: QuarantinePreparePhase::RandomName,
                ..
            })
        ));
        assert!(tmp.path().join("candidate.raw").exists());

        drop(queue);
        let reopened = open_test_queue(tmp.path());
        let quarantine_id = [0x44; 16];
        let publication = reopened
            .publish_quarantine_object_with_ids(
                reopened.root_fd(),
                "candidate.raw",
                crate::QuarantineReason::EnvelopeCorrupt,
                QUARANTINE_NAME_ATTEMPTS,
                || Ok(quarantine_id),
            )
            .unwrap();
        assert_eq!(publication.quarantine_id, quarantine_id);
    }

    #[test]
    fn quarantine_name_collisions_retry_without_overwrite_and_are_bounded() {
        let first_id = [0x11; 16];
        let second_id = [0x22; 16];
        let reason = crate::QuarantineReason::EnvelopeCorrupt;

        let (tmp, queue) = queue_with_quarantine_candidate();
        let first_name = steadq_names::quarantine_filename(&first_id, reason as u16);
        std::fs::write(tmp.path().join("quarantine").join(&first_name), b"distinct").unwrap();
        let mut ids = [first_id, second_id].into_iter();
        let publication = queue
            .publish_quarantine_object_with_ids(
                queue.root_fd(),
                "candidate.raw",
                reason,
                QUARANTINE_NAME_ATTEMPTS,
                || Ok(ids.next().unwrap()),
            )
            .unwrap();
        assert_eq!(publication.quarantine_id, second_id);
        assert_eq!(publication.attempts_consumed, 2);
        assert_eq!(
            std::fs::read(tmp.path().join("quarantine").join(first_name)).unwrap(),
            b"distinct"
        );

        let (tmp, queue) = queue_with_quarantine_candidate();
        let collision_name = steadq_names::quarantine_filename(&first_id, reason as u16);
        std::fs::write(
            tmp.path().join("quarantine").join(&collision_name),
            b"distinct",
        )
        .unwrap();
        let mut attempts = 0;
        let failure = queue
            .publish_quarantine_object_with_ids(
                queue.root_fd(),
                "candidate.raw",
                reason,
                QUARANTINE_NAME_ATTEMPTS,
                || {
                    attempts += 1;
                    Ok(first_id)
                },
            )
            .unwrap_err();
        assert_eq!(attempts, QUARANTINE_NAME_ATTEMPTS);
        assert_eq!(failure.attempts_consumed(), QUARANTINE_NAME_ATTEMPTS);
        assert!(matches!(
            failure,
            QuarantinePublishFailure::CollisionExhausted {
                attempts: QUARANTINE_NAME_ATTEMPTS,
                last_quarantine_id,
                ..
            } if last_quarantine_id == first_id
        ));
        assert_eq!(
            std::fs::read(tmp.path().join("candidate.raw")).unwrap(),
            b"candidate"
        );
        assert_eq!(
            std::fs::read(tmp.path().join("quarantine").join(collision_name)).unwrap(),
            b"distinct"
        );

        let (tmp, queue) = queue_with_quarantine_candidate();
        let collision_name = steadq_names::quarantine_filename(&first_id, reason as u16);
        std::fs::write(
            tmp.path().join("quarantine").join(&collision_name),
            b"distinct",
        )
        .unwrap();
        let failure = queue
            .publish_quarantine_object_with_ids(queue.root_fd(), "candidate.raw", reason, 1, || {
                Ok(first_id)
            })
            .unwrap_err();
        assert!(matches!(
            failure,
            QuarantinePublishFailure::BudgetExhausted {
                attempts: 1,
                last_quarantine_id,
                ..
            } if last_quarantine_id == first_id
        ));
        assert_eq!(
            std::fs::read(tmp.path().join("candidate.raw")).unwrap(),
            b"candidate"
        );
        assert_eq!(
            std::fs::read(tmp.path().join("quarantine").join(collision_name)).unwrap(),
            b"distinct"
        );
    }

    #[test]
    fn fsck_reports_unexpected_entries() {
        let tmp = TempDir::new().unwrap();
        init_test_queue(tmp.path());
        let queue = open_test_queue(tmp.path());
        // Place an unexpected file directly in a ready shard directory.
        let ready_shard = tmp.path().join("ready/0000");
        std::fs::write(ready_shard.join("unexpected.txt"), b"garbage").unwrap();
        // Place an unexpected file in a deep shard (delayed bucket/shard).
        std::fs::create_dir_all(tmp.path().join("delayed/0000000000000000/0001")).unwrap();
        std::fs::write(
            tmp.path().join("delayed/0000000000000000/0001/stray.bin"),
            b"garbage",
        )
        .unwrap();
        // Place an unexpected non-directory file in a leased boot dir.
        std::fs::create_dir_all(tmp.path().join(" leased/boot-test")).unwrap();
        std::fs::write(tmp.path().join("leased/not-a-dir.txt"), b"garbage").unwrap();

        let report = queue.fsck(&FsckOptions::default());
        let unexpected: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.finding_type == "unexpected_entry")
            .collect();
        assert!(
            !unexpected.is_empty(),
            "expected unexpected_entry findings, got {} findings: {:?}",
            report.findings.len(),
            report.findings
        );

        // A clean queue should have zero objects and zero findings.
        let clean_tmp = TempDir::new().unwrap();
        init_test_queue(clean_tmp.path());
        let clean_queue = open_test_queue(clean_tmp.path());
        let clean_report = clean_queue.fsck(&FsckOptions::default());
        assert_eq!(
            clean_report.total_objects, 0,
            "empty queue should have zero objects"
        );
    }

    #[test]
    fn fsck_clean_queue() {
        let tmp = TempDir::new().unwrap();
        init_test_queue(tmp.path());
        let queue = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        let report = queue.fsck(&FsckOptions::default());
        assert_eq!(report.findings.len(), 0);
        assert_eq!(report.total_objects, 0);
    }

    #[test]
    fn fsck_counts_objects_across_state_directories() {
        let tmp = TempDir::new().unwrap();
        init_test_queue(tmp.path());
        let mut queue = open_test_queue(tmp.path());
        for payload in [b"one".as_slice(), b"two".as_slice(), b"three".as_slice()] {
            let outcome = queue.enqueue(EnqueueInput {
                maximum_attempts: 3,
                content_type: "x".into(),
                payload: payload.to_vec(),
                ..Default::default()
            });
            assert!(matches!(outcome, crate::EnqueueOutcome::Committed(_)));
        }
        // Lease and ack the first job: it becomes a full receipt.
        let lease = match queue.lease(0, 30_000_000_000) {
            crate::LeaseOutcome::Leased(info) => info,
            other => panic!("expected a lease, got {other:?}"),
        };
        assert!(matches!(queue.ack(&lease), crate::AckOutcome::Acked));
        // Lease the second job and hold it: it stays leased.
        match queue.lease(0, 30_000_000_000) {
            crate::LeaseOutcome::Leased(_) => {}
            other => panic!("expected a second lease, got {other:?}"),
        }

        let queue = open_test_queue(tmp.path());
        let report = queue.fsck(&FsckOptions::default());
        // one ready + one leased + one full receipt = 3
        assert_eq!(report.total_objects, 3);
    }

    #[test]
    fn fsck_preserves_non_ascii_name_bytes() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let tmp = TempDir::new().unwrap();
        init_test_queue(tmp.path());
        let shard = tmp.path().join("ready/0000");
        // Filesystems with mandatory UTF-8 names (ZFS utf8only, ext4 strict
        // encoding) reject non-UTF-8 names with EILSEQ; the property is
        // untestable there.
        match std::fs::write(shard.join(OsStr::from_bytes(b"probe-\x80")), b"") {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(libc::EILSEQ) => return,
            Err(e) => panic!("probe write failed: {e}"),
        }
        std::fs::remove_file(shard.join(OsStr::from_bytes(b"probe-\x80"))).unwrap();
        std::fs::write(shard.join(OsStr::from_bytes(b"bad-\x80")), b"a").unwrap();
        std::fs::write(shard.join(OsStr::from_bytes(b"bad-\x81")), b"b").unwrap();
        std::fs::write(shard.join("café"), b"c").unwrap();
        let queue = open_test_queue(tmp.path());

        let mut paths = queue
            .fsck(&FsckOptions::default())
            .findings
            .into_iter()
            .filter(|finding| finding.finding_type == "invalid_name_encoding")
            .map(|finding| finding.relative_path)
            .collect::<Vec<_>>();
        paths.sort();
        assert_eq!(
            paths,
            [
                "ready/0000/<bytes:6261642d80>",
                "ready/0000/<bytes:6261642d81>",
                "ready/0000/<bytes:636166c3a9>",
            ]
        );
    }

    #[test]
    fn quarantine_list_export_remove() {
        let tmp = TempDir::new().unwrap();
        init_test_queue(tmp.path());
        let queue = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();

        let qid = [0x11u8; 16];
        let reason = 0x0001u16;
        let name = steadq_names::quarantine_filename(&qid, reason);
        let qdir = tmp.path().join("quarantine");
        std::fs::create_dir_all(&qdir).unwrap();
        let payload = b"quarantined-bytes";
        std::fs::write(qdir.join(&name), payload).unwrap();

        let listed = queue.list_quarantine();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].quarantine_id, qid);
        assert_eq!(listed[0].reason, reason);

        let found = queue.find_quarantine(&qid).unwrap();
        assert_eq!(found.filename, name);

        let out = tmp.path().join("export.raw");
        let n = queue.export_quarantine(&qid, &out).unwrap();
        assert_eq!(n, payload.len() as u64);
        assert_eq!(std::fs::read(&out).unwrap(), payload);

        assert!(queue.remove_quarantine(&qid).unwrap());
        assert!(queue.list_quarantine().is_empty());
        assert!(!queue.remove_quarantine(&qid).unwrap());
    }

    #[test]
    fn fsck_shard_extraction_requires_each_exact_path_shape() {
        let tmp = TempDir::new().unwrap();
        init_test_queue(tmp.path());
        let queue = open_test_queue(tmp.path());

        let cases: &[(&str, &[&str], Option<&str>)] = &[
            ("ready", &["ready", "0001", "job.sqj"], Some("0001")),
            ("ready", &["ready", "0001"], None),
            ("ready", &["ready", "0001", "job.sqj", "extra"], None),
            (
                "leased",
                &["leased", "boot", "bucket", "0002", "job.sqj"],
                Some("0002"),
            ),
            ("leased", &["leased", "boot", "bucket", "0002"], None),
            (
                "delayed",
                &["delayed", "bucket", "0003", "job.sqj"],
                Some("0003"),
            ),
            ("delayed", &["delayed", "bucket", "0003"], None),
            ("dead", &["dead", "bucket", "0004", "job.sqj"], Some("0004")),
            (
                "receipts",
                &["receipts", "bucket", "0005", "job.rct"],
                Some("0005"),
            ),
            ("unknown", &["unknown", "bucket", "0006", "job"], None),
        ];

        for (state, parts, expected) in cases {
            assert_eq!(queue.fsck_extract_shard_hex(state, parts), *expected);
        }
    }

    #[test]
    fn fsck_finds_valid_job() {
        let tmp = TempDir::new().unwrap();
        init_test_queue(tmp.path());
        let mut queue = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        });
        drop(queue);

        let queue2 = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        let report = queue2.fsck(&FsckOptions::default());
        assert_eq!(report.total_objects, 1);
        assert_eq!(report.structurally_verified, 1);
        assert_eq!(report.findings.len(), 0);
    }

    #[test]
    fn fsck_deep_verifies_payload() {
        let tmp = TempDir::new().unwrap();
        init_test_queue(tmp.path());
        let mut queue = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"payload data here".to_vec(),
            ..Default::default()
        });
        drop(queue);

        let queue2 = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        let report = queue2.fsck(&FsckOptions {
            mode: FsckMode::Check,
            depth: FsckDepth::Deep,
        });
        assert_eq!(report.total_objects, 1);
        assert_eq!(report.structurally_verified, 1);
        assert_eq!(report.payloads_deep_verified, 1);
        assert_eq!(report.findings.len(), 0);
    }

    #[test]
    fn fsck_detects_header_corruption() {
        let tmp = TempDir::new().unwrap();
        init_test_queue(tmp.path());
        let mut queue = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        });
        drop(queue);

        // Corrupt a header byte in the ready object
        let ready_dir = tmp.path().join("ready");
        for shard_dir in std::fs::read_dir(&ready_dir).unwrap() {
            let shard_dir = shard_dir.unwrap().path();
            for entry in std::fs::read_dir(&shard_dir).unwrap() {
                let entry = entry.unwrap().path();
                use std::io::{Seek, SeekFrom, Write};
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&entry)
                    .unwrap();
                f.seek(SeekFrom::Start(20)).unwrap();
                f.write_all(&[0xFF]).unwrap();
                f.sync_all().unwrap();
            }
        }

        let queue2 = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        let report = queue2.fsck(&FsckOptions::default());
        assert!(!report.findings.is_empty());
        assert_eq!(report.structurally_verified, 0);
    }

    #[test]
    fn fsck_repair_quarantines_corrupt_header() {
        let tmp = TempDir::new().unwrap();
        init_test_queue(tmp.path());
        let mut queue = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        });
        drop(queue);

        // Corrupt byte 32 (job_id region) - causes header/filename mismatch
        let ready_dir = tmp.path().join("ready");
        for shard_dir in std::fs::read_dir(&ready_dir).unwrap() {
            let shard_dir = shard_dir.unwrap().path();
            for entry in std::fs::read_dir(&shard_dir).unwrap() {
                let entry = entry.unwrap().path();
                use std::io::{Read, Seek, SeekFrom, Write};
                let mut f = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&entry)
                    .unwrap();
                f.seek(SeekFrom::Start(32)).unwrap();
                let mut original = [0_u8; 1];
                f.read_exact(&mut original).unwrap();
                let corrupted = different_byte(original[0]);
                f.seek(SeekFrom::Start(32)).unwrap();
                f.write_all(&[corrupted]).unwrap();
                f.sync_all().unwrap();
            }
        }

        let queue2 = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        let report = queue2.fsck(&FsckOptions {
            mode: FsckMode::Repair,
            depth: FsckDepth::Structural,
        });
        assert!(!report.findings.is_empty());
        assert!(!report.quarantined.is_empty());
    }

    #[test]
    fn quarantine_opened_receipt_rejects_path_replacement() {
        let tmp = TempDir::new().unwrap();
        init_test_queue(tmp.path());
        let queue = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        let filename = "candidate.rct";
        let candidate = tmp.path().join(filename);
        let displaced = tmp.path().join("displaced.rct");
        std::fs::write(&candidate, b"corrupt").unwrap();
        let opened = steadq_fs_linux::openat(
            queue.root_fd(),
            filename,
            crate::queue::verified::receipt_write_open_flags(),
            0,
        )
        .unwrap();
        std::fs::rename(&candidate, &displaced).unwrap();
        std::fs::write(&candidate, b"replacement").unwrap();
        let mut report = FsckReport::default();

        let error = queue
            .quarantine_opened_object(
                queue.root_fd(),
                filename,
                filename,
                &opened,
                crate::QuarantineReason::EnvelopeCorrupt,
                &mut report,
            )
            .unwrap_err();

        assert!(matches!(
            error,
            QuarantinePublishFailure::Preparation {
                phase: QuarantinePreparePhase::SourceIdentity,
                ..
            }
        ));
        assert_eq!(std::fs::read(&candidate).unwrap(), b"replacement");
        assert_eq!(std::fs::read(&displaced).unwrap(), b"corrupt");
        assert!(report.quarantined.is_empty());
        assert!(queue.list_quarantine().is_empty());
    }

    #[test]
    fn receipt_repair_requires_an_opened_regular_candidate() {
        let tmp = TempDir::new().unwrap();
        init_test_queue(tmp.path());
        let queue = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        let target = tmp.path().join("target.raw");
        let candidate = tmp.path().join("candidate.rct");
        std::fs::write(&target, b"target").unwrap();
        std::os::unix::fs::symlink(&target, &candidate).unwrap();
        let mut report = FsckReport::default();

        queue.repair_quarantine_candidate(
            "receipts",
            queue.root_fd(),
            "candidate.rct",
            "candidate.rct",
            crate::QuarantineReason::NonRegularFile,
            &mut report,
        );

        assert!(candidate
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read(&target).unwrap(), b"target");
        assert!(report.quarantined.is_empty());
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.finding_type == "quarantine_failed"));
    }

    #[test]
    fn receipt_repair_quarantines_locked_regular_candidate() {
        let tmp = TempDir::new().unwrap();
        init_test_queue(tmp.path());
        let queue = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        let candidate = tmp.path().join("candidate.rct");
        std::fs::write(&candidate, b"corrupt").unwrap();
        let mut report = FsckReport::default();

        queue.repair_quarantine_candidate(
            "receipts",
            queue.root_fd(),
            "candidate.rct",
            "candidate.rct",
            crate::QuarantineReason::EnvelopeCorrupt,
            &mut report,
        );

        assert!(!candidate.exists());
        assert_eq!(report.quarantined.len(), 1);
        assert_eq!(queue.list_quarantine().len(), 1);
        assert!(!report
            .findings
            .iter()
            .any(|finding| finding.finding_type == "quarantine_failed"));
    }
}
