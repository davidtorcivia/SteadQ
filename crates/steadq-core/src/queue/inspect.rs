// Payload reads, inspect, dead-letter admin, and receipt probes.
use super::*;

impl Queue {
    // Read and verify the payload of a leased job.
    /// Validates source identity, then verifies envelope digest,
    /// then hashes the payload and compares to the header digest.
    /// Returns Ok(()) on success, Err(PayloadCorrupt) if the digest does not match.
    pub fn verify_lease_payload(&self, lease: &LeaseInfo) -> Result<(), Error> {
        let source = match self.open_and_validate_current_lease(lease)? {
            Some(source) => source,
            None => return Err(Error::QueueCorrupt("lease source not found".into())),
        };
        self.verify_payload_on_fd(source.file_fd.as_fd())
    }

    /// Verify the payload digest on an already-open file descriptor.
    /// Central verifier is the single source of truth; this wrapper preserves
    /// the existing Error mapping for callers that have not yet adopted
    /// VerificationError directly.
    pub(super) fn verify_payload_on_fd(&self, fd: BorrowedFd<'_>) -> Result<(), Error> {
        verified::verify_job_on_fd(fd)
            .map(|_| ())
            .map_err(Error::from)
    }

    /// Verify only the envelope and size, without hashing payload bytes.
    /// Used by inspection paths that have not yet delivered payload.
    pub(super) fn verify_envelope_on_fd(
        &self,
        fd: BorrowedFd<'_>,
    ) -> Result<verified::VerifiedJob, Error> {
        verified::verify_envelope_on_fd(fd).map_err(Error::from)
    }

    pub(super) fn quarantine_corrupt_lease(
        &self,
        leased_dir_fd: BorrowedFd<'_>,
        leased_name: &str,
        held_fd: BorrowedFd<'_>,
    ) -> Result<(), engine::MoveFailure> {
        let held_stat = fs::fstat(held_fd).map_err(|source| engine::MoveFailure::NotCommitted {
            phase: engine::MovePhase::PreRename,
            source,
        })?;
        let name_stat = fs::fstatat(leased_dir_fd, leased_name).map_err(|source| {
            engine::MoveFailure::NotCommitted {
                phase: engine::MovePhase::PreRename,
                source,
            }
        })?;
        if held_stat.st_dev != name_stat.st_dev || held_stat.st_ino != name_stat.st_ino {
            return Err(engine::MoveFailure::SourceMissing);
        }
        let source_identity = engine::MoveIdentity::new(held_stat.st_dev, held_stat.st_ino);

        let qid = fs::random_128bit().map_err(|source| engine::MoveFailure::NotCommitted {
            phase: engine::MovePhase::PreRename,
            source,
        })?;
        let q_name =
            steadq_names::quarantine_filename(&qid, QuarantineReason::PayloadCorrupt as u16);
        self.ensure_dir("quarantine")
            .map_err(|source| engine::MoveFailure::NotCommitted {
                phase: engine::MovePhase::PreRename,
                source,
            })?;
        let q_dir_fd = open_relative(self.root_fd.as_fd(), "quarantine").map_err(|source| {
            engine::MoveFailure::NotCommitted {
                phase: engine::MovePhase::PreRename,
                source,
            }
        })?;

        engine::move_witnessed_noreplace(
            leased_dir_fd,
            leased_name,
            q_dir_fd.as_fd(),
            &q_name,
            source_identity,
        )
    }
    /// Read a chunk of a leased job's payload at the given offset.
    /// Returns the number of bytes read (0 at EOF).
    /// Validates source identity before reading.
    pub fn read_lease_payload_chunk(
        &self,
        lease: &LeaseInfo,
        buf: &mut [u8],
        offset: u64,
    ) -> Result<usize, Error> {
        let source = match self.open_and_validate_current_lease(lease)? {
            Some(source) => source,
            None => return Err(Error::QueueCorrupt("lease source not found".into())),
        };
        // Verify payload before delivering any bytes.
        if let Err(e) = self.verify_payload_on_fd(source.file_fd.as_fd()) {
            if matches!(e, Error::PayloadCorrupt) {
                if let Err(engine::MoveFailure::OutcomeUnknown {
                    phase,
                    source: detail,
                }) = self.quarantine_corrupt_lease(
                    source.directory_fd.as_fd(),
                    &source.name,
                    source.file_fd.as_fd(),
                ) {
                    return Err(Error::QueueCorrupt(format!(
                        "payload is corrupt and quarantine is indeterminate at {phase:?}: {detail}"
                    )));
                }
            }
            return Err(e);
        }
        let mut header_buf = [0u8; 128];
        fs::pread_exact(source.file_fd.as_fd(), &mut header_buf, 0).map_err(Error::from)?;
        let header =
            FixedHeader::decode(&header_buf).map_err(|e| Error::QueueCorrupt(e.to_string()))?;
        let ext_len = header.extension_header_length as usize;
        let payload_start = (128 + ext_len) as u64;
        let payload_len = header.payload_length;
        if offset >= payload_len {
            return Ok(0);
        }
        let remaining = payload_len
            .checked_sub(offset)
            .expect("offset below payload length was checked");
        let to_read = (buf.len() as u64).min(remaining) as usize;
        let abs_offset = payload_start + offset;
        let n = fs::pread(source.file_fd.as_fd(), &mut buf[..to_read], abs_offset)
            .map_err(Error::from)?;
        Ok(n)
    }

    /// Stream a leased job's payload with O(1) validation/open.
    /// Opens the file once, validates identity once, reads header once,
    /// then performs pread calls on the held fd.
    pub fn stream_lease_payload<F: FnMut(&[u8]) -> Result<(), Error>>(
        &self,
        lease: &LeaseInfo,
        chunk_size: usize,
        mut f: F,
    ) -> Result<(), Error> {
        let source = match self.open_and_validate_current_lease(lease)? {
            Some(source) => source,
            None => return Err(Error::QueueCorrupt("lease source not found".into())),
        };
        // Verify payload before streaming any bytes.
        if let Err(e) = self.verify_payload_on_fd(source.file_fd.as_fd()) {
            if matches!(e, Error::PayloadCorrupt) {
                if let Err(engine::MoveFailure::OutcomeUnknown {
                    phase,
                    source: detail,
                }) = self.quarantine_corrupt_lease(
                    source.directory_fd.as_fd(),
                    &source.name,
                    source.file_fd.as_fd(),
                ) {
                    return Err(Error::QueueCorrupt(format!(
                        "payload is corrupt and quarantine is indeterminate at {phase:?}: {detail}"
                    )));
                }
            }
            return Err(e);
        }

        let mut header_buf = [0u8; 128];
        fs::pread_exact(source.file_fd.as_fd(), &mut header_buf, 0).map_err(Error::from)?;
        let header =
            FixedHeader::decode(&header_buf).map_err(|e| Error::QueueCorrupt(e.to_string()))?;

        let ext_len = header.extension_header_length as usize;
        let payload_start = (128 + ext_len) as u64;
        let payload_len = header.payload_length;

        let cap = chunk_size.clamp(4096, 1 << 20);
        let mut buf = vec![0u8; cap];
        let mut offset = 0u64;
        while offset < payload_len {
            let remaining = payload_len
                .checked_sub(offset)
                .expect("offset below payload length was checked");
            let to_read = (buf.len() as u64).min(remaining) as usize;
            let n = fs::pread(
                source.file_fd.as_fd(),
                &mut buf[..to_read],
                payload_start + offset,
            )
            .map_err(Error::from)?;
            if n == 0 {
                return Err(Error::QueueCorrupt("unexpected EOF during stream".into()));
            }
            f(&buf[..n])?;
            offset = offset
                .checked_add(n as u64)
                .expect("stream offset cannot exceed the verified payload length");
        }
        Ok(())
    }

    /// Open a verified payload reader for a lease. The payload is hashed
    /// once at construction; subsequent `read_at` calls do not re-hash.
    pub fn open_verified_payload_reader(
        &self,
        lease: &LeaseInfo,
    ) -> Result<Option<VerifiedPayloadReader>, Error> {
        let source = match self.open_and_validate_current_lease(lease)? {
            Some(source) => source,
            None => return Ok(None),
        };
        // Verify payload before allowing reads.
        if let Err(e) = self.verify_payload_on_fd(source.file_fd.as_fd()) {
            if matches!(e, Error::PayloadCorrupt) {
                if let Err(engine::MoveFailure::OutcomeUnknown {
                    phase,
                    source: detail,
                }) = self.quarantine_corrupt_lease(
                    source.directory_fd.as_fd(),
                    &source.name,
                    source.file_fd.as_fd(),
                ) {
                    return Err(Error::QueueCorrupt(format!(
                        "payload is corrupt and quarantine is indeterminate at {phase:?}: {detail}"
                    )));
                }
            }
            return Err(e);
        }
        let mut header_buf = [0u8; 128];
        fs::pread_exact(source.file_fd.as_fd(), &mut header_buf, 0).map_err(Error::from)?;
        let header =
            FixedHeader::decode(&header_buf).map_err(|e| Error::QueueCorrupt(e.to_string()))?;
        let ext_len = header.extension_header_length as usize;
        Ok(Some(VerifiedPayloadReader {
            file_fd: source.file_fd,
            payload_start: (128 + ext_len) as u64,
            payload_len: header.payload_length,
        }))
    }

    /// Diagnostic lookup: find all states for a job_id.
    /// Scans active and terminal states for the computed shard.
    pub fn inspect(&self, job_id: &[u8; 16]) -> Vec<Snapshot> {
        let mut results = Vec::new();
        let shard = compute_shard(self.format.queue_id(), job_id, self.format.shard_count());
        let shard_str = shard_hex(shard);

        // Check ready
        let ready_dir = format!("ready/{shard_str}");
        if let Ok(dir_fd) = open_relative(self.root_fd.as_fd(), &ready_dir) {
            if let Ok(entries) = fs::read_dir_entries(dir_fd.as_fd()) {
                for entry in entries {
                    let Some(entry) = entry.as_ascii_str() else {
                        continue;
                    };
                    if let Ok(parsed) = steadq_names::parse_ready(entry) {
                        if parsed.common.job_id == *job_id {
                            results.push(Snapshot {
                                job_id: *job_id,
                                state: "ready".into(),
                                generation: parsed.common.generation,
                                attempt: parsed.common.attempt,
                                maximum_attempts: parsed.common.maximum_attempts,
                                shard,
                                relative_path: format!("{ready_dir}/{entry}"),
                                size: 0,
                            });
                        }
                    } else if let Ok(parsed) = steadq_names::parse_leased(entry) {
                        if parsed.common.job_id == *job_id {
                            results.push(Snapshot {
                                job_id: *job_id,
                                state: "leased".into(),
                                generation: parsed.common.generation,
                                attempt: parsed.common.attempt,
                                maximum_attempts: parsed.common.maximum_attempts,
                                shard,
                                relative_path: format!("{ready_dir}/{entry}"),
                                size: 0,
                            });
                        }
                    }
                }
            }
        }

        // Check leased (scan boot dirs)
        if let Ok(leased_root) = fs::open_directory(self.root_fd.as_fd(), "leased") {
            if let Ok(boot_dirs) = fs::read_dir_entries(leased_root.as_fd()) {
                for boot_dir in boot_dirs {
                    let Some(boot_dir) = boot_dir.as_ascii_str() else {
                        continue;
                    };
                    let boot_path = format!("leased/{boot_dir}");
                    if let Ok(boot_fd) = open_relative(self.root_fd.as_fd(), &boot_path) {
                        if let Ok(bucket_dirs) = fs::read_dir_entries(boot_fd.as_fd()) {
                            for bucket_dir in bucket_dirs {
                                let Some(bucket_dir) = bucket_dir.as_ascii_str() else {
                                    continue;
                                };
                                let shard_path = format!("{boot_path}/{bucket_dir}/{shard_str}");
                                if let Ok(shard_fd) =
                                    open_relative(self.root_fd.as_fd(), &shard_path)
                                {
                                    if let Ok(entries) = fs::read_dir_entries(shard_fd.as_fd()) {
                                        for entry in entries {
                                            let Some(entry) = entry.as_ascii_str() else {
                                                continue;
                                            };
                                            if let Ok(parsed) = steadq_names::parse_leased(entry) {
                                                if parsed.common.job_id == *job_id {
                                                    results.push(Snapshot {
                                                        job_id: *job_id,
                                                        state: "leased".into(),
                                                        generation: parsed.common.generation,
                                                        attempt: parsed.common.attempt,
                                                        maximum_attempts: parsed
                                                            .common
                                                            .maximum_attempts,
                                                        shard,
                                                        relative_path: format!(
                                                            "{shard_path}/{entry}"
                                                        ),
                                                        size: 0,
                                                    });
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Check delayed
        if let Ok(delayed_root) = fs::open_directory(self.root_fd.as_fd(), "delayed") {
            if let Ok(bucket_dirs) = fs::read_dir_entries(delayed_root.as_fd()) {
                for bucket_dir in bucket_dirs {
                    let Some(bucket_dir) = bucket_dir.as_ascii_str() else {
                        continue;
                    };
                    let shard_path = format!("delayed/{bucket_dir}/{shard_str}");
                    if let Ok(shard_fd) = open_relative(self.root_fd.as_fd(), &shard_path) {
                        if let Ok(entries) = fs::read_dir_entries(shard_fd.as_fd()) {
                            for entry in entries {
                                let Some(entry) = entry.as_ascii_str() else {
                                    continue;
                                };
                                if let Ok(parsed) = steadq_names::parse_delayed(entry) {
                                    if parsed.common.job_id == *job_id {
                                        results.push(Snapshot {
                                            job_id: *job_id,
                                            state: "delayed".into(),
                                            generation: parsed.common.generation,
                                            attempt: parsed.common.attempt,
                                            maximum_attempts: parsed.common.maximum_attempts,
                                            shard,
                                            relative_path: format!("{shard_path}/{entry}"),
                                            size: 0,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Check dead
        if let Ok(dead_root) = fs::open_directory(self.root_fd.as_fd(), "dead") {
            if let Ok(bucket_dirs) = fs::read_dir_entries(dead_root.as_fd()) {
                for bucket_dir in bucket_dirs {
                    let Some(bucket_dir) = bucket_dir.as_ascii_str() else {
                        continue;
                    };
                    let shard_path = format!("dead/{bucket_dir}/{shard_str}");
                    if let Ok(shard_fd) = open_relative(self.root_fd.as_fd(), &shard_path) {
                        if let Ok(entries) = fs::read_dir_entries(shard_fd.as_fd()) {
                            for entry in entries {
                                let Some(entry) = entry.as_ascii_str() else {
                                    continue;
                                };
                                if let Ok(parsed) = steadq_names::parse_dead(entry) {
                                    if parsed.common.job_id == *job_id {
                                        results.push(Snapshot {
                                            job_id: *job_id,
                                            state: "dead".into(),
                                            generation: parsed.common.generation,
                                            attempt: parsed.common.attempt,
                                            maximum_attempts: parsed.common.maximum_attempts,
                                            shard,
                                            relative_path: format!("{shard_path}/{entry}"),
                                            size: 0,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Check receipts
        if let Ok(receipts_root) = fs::open_directory(self.root_fd.as_fd(), "receipts") {
            if let Ok(bucket_dirs) = fs::read_dir_entries(receipts_root.as_fd()) {
                for bucket_dir in bucket_dirs {
                    let Some(bucket_dir) = bucket_dir.as_ascii_str() else {
                        continue;
                    };
                    let shard_path = format!("receipts/{bucket_dir}/{shard_str}");
                    if let Ok(shard_fd) = open_relative(self.root_fd.as_fd(), &shard_path) {
                        if let Ok(entries) = fs::read_dir_entries(shard_fd.as_fd()) {
                            for entry in entries {
                                let Some(entry) = entry.as_ascii_str() else {
                                    continue;
                                };
                                if let Ok(parsed) = steadq_names::parse_receipt(entry) {
                                    if parsed.common.job_id == *job_id {
                                        let file_fd = match fs::openat(
                                            shard_fd.as_fd(),
                                            entry,
                                            verified::receipt_read_open_flags(),
                                            0,
                                        ) {
                                            Ok(file_fd) => file_fd,
                                            Err(_) => continue,
                                        };
                                        if verified::verify_receipt_on_fd(
                                            file_fd.as_fd(),
                                            verified::ReceiptContext {
                                                queue_id: self.format.queue_id(),
                                                shard_count: self.format.shard_count(),
                                                terminal_bucket_width_ns: self
                                                    .format
                                                    .terminal_bucket_width_ns(),
                                                max_payload_length: self
                                                    .format
                                                    .max_payload_length(),
                                                bucket: bucket_dir,
                                                shard: &shard_str,
                                                filename: entry,
                                            },
                                            None,
                                        )
                                        .is_ok()
                                        {
                                            results.push(Snapshot {
                                                job_id: *job_id,
                                                state: "receipt".into(),
                                                generation: parsed.common.generation,
                                                attempt: parsed.common.attempt,
                                                maximum_attempts: parsed.common.maximum_attempts,
                                                shard,
                                                relative_path: format!("{shard_path}/{entry}"),
                                                size: 0,
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        results
    }

    /// Export a dead job's raw bytes to an output file. Opens the job through
    /// the root capability with O_NOFOLLOW, not via a pathname.
    pub fn export_dead(&self, job_id: &[u8; 16], output: &std::path::Path) -> Result<u64, Error> {
        let snapshot = self
            .inspect(job_id)
            .into_iter()
            .find(|s| s.state == "dead")
            .ok_or_else(|| Error::QueueCorrupt("dead job not found".into()))?;

        let (dir_rel, name) = snapshot
            .relative_path
            .rsplit_once('/')
            .ok_or_else(|| Error::QueueCorrupt("invalid dead path".into()))?;

        let dir_fd = open_relative(self.root_fd.as_fd(), dir_rel).map_err(Error::from)?;
        let file_fd = fs::openat(
            dir_fd.as_fd(),
            name,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )
        .map_err(Error::from)?;

        let stat = fs::fstat(file_fd.as_fd()).map_err(Error::from)?;
        if stat.st_size < 0 {
            return Err(Error::QueueCorrupt("negative file size".into()));
        }
        let size = stat.st_size as u64;

        let mut out = std::fs::File::create(output).map_err(Error::from)?;
        let mut offset = 0u64;
        let mut buf = vec![0u8; 65536];
        while offset < size {
            let n = fs::pread(file_fd.as_fd(), &mut buf, offset).map_err(Error::from)?;
            if n == 0 {
                break;
            }
            use std::io::Write;
            out.write_all(&buf[..n]).map_err(Error::from)?;
            offset += n as u64;
        }
        out.sync_all().map_err(Error::from)?;
        Ok(offset)
    }

    /// Remove a dead job through the phase-aware unlink executor.
    pub fn remove_dead(&self, job_id: &[u8; 16]) -> Result<bool, Error> {
        let snapshot = self
            .inspect(job_id)
            .into_iter()
            .find(|s| s.state == "dead")
            .ok_or_else(|| Error::QueueCorrupt("dead job not found".into()))?;

        let (dir_rel, name) = snapshot
            .relative_path
            .rsplit_once('/')
            .ok_or_else(|| Error::QueueCorrupt("invalid dead path".into()))?;

        let dir_fd = open_relative(self.root_fd.as_fd(), dir_rel).map_err(Error::from)?;

        match engine::unlink_verified(dir_fd.as_fd(), name) {
            Ok(()) => Ok(true),
            Err(engine::UnlinkFailure::SourceMissing) => Ok(false),
            Err(engine::UnlinkFailure::NotCommitted { phase, source }) => {
                Err(match Error::from(source) {
                    Error::IoFailure(message) => {
                        Error::IoFailure(format!("dead removal failed at {phase:?}: {message}"))
                    }
                    classified => classified,
                })
            }
            Err(engine::UnlinkFailure::OutcomeUnknown { phase, source }) => Err(Error::IoFailure(
                format!("dead removal indeterminate at {phase:?}: {source}"),
            )),
        }
    }

    /// Duplicate acknowledgment probe: check if a receipt exists for this lease.
    /// Probes exact receipt filenames across retained terminal buckets.
    pub fn check_duplicate_ack(&self, lease: &LeaseInfo) -> AckOutcome {
        let wall_floor = match self.authenticated_wall_floor() {
            Ok(wall_floor) => wall_floor,
            Err(error) => return AckOutcome::NotCommitted(error),
        };
        if self.check_duplicate_ack_bounded(lease, wall_floor) {
            AckOutcome::AlreadyAcked
        } else {
            AckOutcome::LeaseLost
        }
    }

    /// Authenticate an active-state object structurally.
    /// Validates: file type, link count, header, envelope digest, file size,
    /// name tag, shard placement, and header/name consistency with typed path context.
    /// Returns the validated header on success.
    pub(crate) fn validate_active_object(
        &self,
        dir_fd: BorrowedFd<'_>,
        name: &str,
        ctx: &ActivePathContext,
    ) -> Result<FixedHeader, Error> {
        // Stat with NOFOLLOW
        let stat = fs::fstatat(dir_fd, name).map_err(Error::from)?;

        // Regular file
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err(Error::QueueCorrupt(format!("{name}: not a regular file")));
        }

        // Link count
        if stat.st_nlink != 1 {
            return Err(Error::QueueCorrupt(format!(
                "{name}: unexpected link count {}",
                stat.st_nlink
            )));
        }

        // Use central verifier for header, extension, envelope, and size.
        // stat has already been collected for mode and nlink; verify_envelope_on_fd
        // will re-stat the fd for size, which is fine since the fd is held open.
        let file_fd = fs::openat(dir_fd, name, libc::O_RDONLY, 0).map_err(Error::from)?;
        let verified = self.verify_envelope_on_fd(file_fd.as_fd())?;
        let header = verified.header();

        // Check queue-configured payload limit
        if !payload_length_is_valid(header.payload_length, self.format.max_payload_length()) {
            return Err(Error::QueueCorrupt(format!(
                "payload length {} exceeds queue limit {}",
                header.payload_length,
                self.format.max_payload_length()
            )));
        }

        // Parse and verify filename with typed path context and tag authentication.
        let (job_id, max_att, path_shard_str) = match ctx {
            ActivePathContext::Ready { shard } => {
                let p = steadq_names::parse_ready(name)
                    .map_err(|_| Error::QueueCorrupt("invalid ready filename".into()))?;
                if !p.authenticate_tag(self.format.queue_id(), shard) {
                    return Err(Error::QueueCorrupt("name tag mismatch".into()));
                }
                (p.common.job_id, p.common.maximum_attempts, shard.clone())
            }
            ActivePathContext::Leased {
                boot_id,
                bucket,
                shard,
            } => {
                let p = steadq_names::parse_leased(name)
                    .map_err(|_| Error::QueueCorrupt("invalid leased filename".into()))?;
                if !p.authenticate_tag(self.format.queue_id(), boot_id, bucket, shard) {
                    return Err(Error::QueueCorrupt("name tag mismatch".into()));
                }
                let expected_bucket = steadq_math::lease_bucket(
                    p.boottime_deadline_ns,
                    self.format.lease_bucket_width_ns(),
                )
                .ok_or_else(|| Error::QueueCorrupt("invalid lease bucket width".into()))?;
                let expected_bucket_str = steadq_names::bucket_hex(expected_bucket);
                if expected_bucket_str != *bucket {
                    return Err(Error::QueueCorrupt(format!(
                        "leased bucket mismatch: path {bucket} != expected {expected_bucket_str}"
                    )));
                }
                (p.common.job_id, p.common.maximum_attempts, shard.clone())
            }
            ActivePathContext::Delayed { bucket, shard } => {
                let p = steadq_names::parse_delayed(name)
                    .map_err(|_| Error::QueueCorrupt("invalid delayed filename".into()))?;
                if !p.authenticate_tag(self.format.queue_id(), bucket, shard) {
                    return Err(Error::QueueCorrupt("name tag mismatch".into()));
                }
                let expected_bucket = steadq_math::ceiling_bucket(
                    p.not_before_ns,
                    self.format.delayed_bucket_width_ns(),
                )
                .ok_or_else(|| Error::QueueCorrupt("invalid delayed bucket width".into()))?;
                let expected_bucket_str = steadq_names::bucket_hex(expected_bucket);
                if expected_bucket_str != *bucket {
                    return Err(Error::QueueCorrupt(format!(
                        "delayed bucket mismatch: path {bucket} != expected {expected_bucket_str}"
                    )));
                }
                (p.common.job_id, p.common.maximum_attempts, shard.clone())
            }
        };

        if header.job_id != job_id {
            return Err(Error::QueueCorrupt(
                "header job_id does not match filename".into(),
            ));
        }
        if header.maximum_attempts != max_att {
            return Err(Error::QueueCorrupt(
                "header maximum_attempts does not match filename".into(),
            ));
        }

        // Verify shard placement
        let computed_shard =
            compute_shard(self.format.queue_id(), &job_id, self.format.shard_count());
        let path_shard = steadq_names::shard_from_hex(&path_shard_str)
            .ok_or_else(|| Error::QueueCorrupt(format!("invalid shard hex: {path_shard_str}")))?;
        if path_shard != computed_shard {
            return Err(Error::QueueCorrupt(format!(
                "shard mismatch: path {path_shard} != computed {computed_shard}"
            )));
        }

        Ok(header.clone())
    }

    /// Bounded duplicate-ack check.
    /// Constructs at most the finite set of exact retained receipt paths
    /// and checks them via fstatat, not by listing receipt contents.
    /// Authenticate a receipt at a specific path.
    pub(super) fn receipt_is_authentic(&self, lease: &LeaseInfo, dir: &str, name: &str) -> bool {
        let Ok(common) = next_identity(ProtocolOperation::Acknowledge, &lease_common(lease)) else {
            return false;
        };
        let expected = verified::ExpectedReceipt {
            common,
            token: lease.token,
            envelope_digest: lease.envelope_digest,
            payload_length: lease.payload_length,
        };
        let dir_fd = match open_relative(self.root_fd.as_fd(), dir) {
            Ok(fd) => fd,
            Err(_) => return false,
        };
        let parts: Vec<&str> = dir.split('/').collect();
        let (bucket, shard_hex) = match parts.len() {
            3 => (parts[1], parts[2]),
            _ => return false,
        };
        let file_fd = match fs::openat(dir_fd.as_fd(), name, verified::receipt_read_open_flags(), 0)
        {
            Ok(f) => f,
            Err(_) => return false,
        };
        verified::verify_receipt_on_fd(
            file_fd.as_fd(),
            verified::ReceiptContext {
                queue_id: self.format.queue_id(),
                shard_count: self.format.shard_count(),
                terminal_bucket_width_ns: self.format.terminal_bucket_width_ns(),
                max_payload_length: self.format.max_payload_length(),
                bucket,
                shard: shard_hex,
                filename: name,
            },
            Some(&expected),
        )
        .is_ok()
    }

    pub(super) fn check_duplicate_ack_bounded(
        &self,
        lease: &LeaseInfo,
        wall_floor: WallFloor,
    ) -> bool {
        let retention = self.options.receipt_retention_ns;
        let width = self.format.terminal_bucket_width_ns();
        let now_bucket = match steadq_math::bucket_number(wall_floor.unix_ns(), width) {
            Some(bucket) => bucket,
            None => return false,
        };
        let retention_buckets = match steadq_math::ceiling_bucket(retention, width) {
            Some(buckets) => buckets,
            None => return false,
        };
        let min_bucket = now_bucket.saturating_sub(retention_buckets + 2);
        let shard = compute_shard(
            self.format.queue_id(),
            &lease.job_id,
            self.format.shard_count(),
        );
        let shard_str = shard_hex(shard);
        let Ok(receipt_common) =
            next_identity(ProtocolOperation::Acknowledge, &lease_common(lease))
        else {
            return false;
        };
        let expected = verified::ExpectedReceipt {
            common: receipt_common.clone(),
            token: lease.token,
            envelope_digest: lease.envelope_digest,
            payload_length: lease.payload_length,
        };
        for bucket_num in min_bucket..=now_bucket {
            let bucket_str = bucket_hex(bucket_num);
            let receipt_name = steadq_names::make_receipt_name(
                self.format.queue_id(),
                &bucket_str,
                &shard_str,
                &receipt_common,
                &lease.token,
            );
            let receipt_dir = format!("receipts/{bucket_str}/{shard_str}");
            if let Ok(dir_fd) = open_relative(self.root_fd.as_fd(), &receipt_dir) {
                if let Ok(file_fd) = fs::openat(
                    dir_fd.as_fd(),
                    &receipt_name,
                    verified::receipt_read_open_flags(),
                    0,
                ) {
                    if verified::verify_receipt_on_fd(
                        file_fd.as_fd(),
                        verified::ReceiptContext {
                            queue_id: self.format.queue_id(),
                            shard_count: self.format.shard_count(),
                            terminal_bucket_width_ns: self.format.terminal_bucket_width_ns(),
                            max_payload_length: self.format.max_payload_length(),
                            bucket: &bucket_str,
                            shard: &shard_str,
                            filename: &receipt_name,
                        },
                        Some(&expected),
                    )
                    .is_ok()
                    {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Resolve an indeterminate operation by probing exact paths.
    /// Resolve an indeterminate operation by authenticating objects.
    /// Validates source/destination by opening them, reading headers, and
    /// comparing job_id and generation against the ticket.
    /// Helper: verify shard placement from a shard hex string.
    pub(super) fn verify_shard_placement(&self, shard_hex: &str, job_id: &[u8; 16]) -> bool {
        let computed = compute_shard(self.format.queue_id(), job_id, self.format.shard_count());
        match steadq_names::shard_from_hex(shard_hex) {
            Some(s) => s == computed,
            None => false,
        }
    }
}
