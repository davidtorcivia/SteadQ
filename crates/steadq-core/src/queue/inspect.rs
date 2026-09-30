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
    #[cfg(test)]
    pub(crate) fn read_lease_payload_chunk(
        &self,
        lease: &LeaseInfo,
        buf: &mut [u8],
        offset: u64,
    ) -> Result<usize, Error> {
        self.open_verified_payload_reader(lease)?
            .ok_or_else(|| Error::QueueCorrupt("lease source not found".into()))?
            .read_at(buf, offset)
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
        let reader = self
            .open_verified_payload_reader(lease)?
            .ok_or_else(|| Error::QueueCorrupt("lease source not found".into()))?;
        let mut buf = vec![0u8; chunk_size.clamp(4096, 1 << 20)];
        let mut offset = 0u64;
        loop {
            let n = reader.read_at(&mut buf, offset)?;
            if n == 0 {
                return Ok(());
            }
            f(&buf[..n])?;
            offset = offset
                .checked_add(n as u64)
                .expect("stream offset cannot exceed the verified payload length");
        }
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
        let verified = match verified::verify_job_on_fd(source.file_fd.as_fd()).map_err(Error::from)
        {
            Ok(verified) => verified,
            Err(e) => {
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
        };
        let header = verified.header();
        Ok(Some(VerifiedPayloadReader {
            file_fd: source.file_fd,
            payload_start: 128 + u64::from(header.extension_header_length),
            payload_len: header.payload_length,
        }))
    }

    /// Diagnostic lookup: find all states for a job_id.
    /// Scans active and terminal states for the computed shard. A missing
    /// directory is empty; any other directory or receipt read failure is an
    /// error rather than a partial answer.
    pub fn inspect(&self, job_id: &[u8; 16]) -> Result<Vec<Snapshot>, Error> {
        let queue_id = self.format.queue_id();
        let shard = compute_shard(queue_id, job_id, self.format.shard_count());
        let shard_str = shard_hex(shard);
        let mut results = Vec::new();
        let mut push = |state: &str, common: &CommonFields, relative_path: String| {
            if common.job_id == *job_id {
                results.push(Snapshot {
                    job_id: *job_id,
                    state: state.into(),
                    generation: common.generation,
                    attempt: common.attempt,
                    maximum_attempts: common.maximum_attempts,
                    shard,
                    relative_path,
                    size: 0,
                });
            }
        };
        let root = self.root_fd.as_fd();

        visit_shard_dirs(root, "ready", 0, &shard_str, &mut |dir, _| {
            for entry in names_in(dir.fd)? {
                if let Ok(parsed) = steadq_names::parse_ready(&entry) {
                    push("ready", &parsed.common, dir.child(&entry));
                } else if let Ok(parsed) = steadq_names::parse_leased(&entry) {
                    push("leased", &parsed.common, dir.child(&entry));
                }
            }
            Ok(())
        })?;
        visit_shard_dirs(root, "leased", 2, &shard_str, &mut |dir, _| {
            for entry in names_in(dir.fd)? {
                if let Ok(parsed) = steadq_names::parse_leased(&entry) {
                    push("leased", &parsed.common, dir.child(&entry));
                }
            }
            Ok(())
        })?;
        visit_shard_dirs(root, "delayed", 1, &shard_str, &mut |dir, _| {
            for entry in names_in(dir.fd)? {
                if let Ok(parsed) = steadq_names::parse_delayed(&entry) {
                    push("delayed", &parsed.common, dir.child(&entry));
                }
            }
            Ok(())
        })?;
        visit_shard_dirs(root, "dead", 1, &shard_str, &mut |dir, bucket| {
            for entry in names_in(dir.fd)? {
                if let Ok(parsed) = steadq_names::parse_dead(&entry) {
                    if parsed.authenticate_tag(queue_id, bucket, &shard_str) {
                        push("dead", &parsed.common, dir.child(&entry));
                    }
                }
            }
            Ok(())
        })?;
        visit_shard_dirs(root, "receipts", 1, &shard_str, &mut |dir, bucket| {
            for entry in names_in(dir.fd)? {
                let Ok(parsed) = steadq_names::parse_receipt(&entry) else {
                    continue;
                };
                if parsed.common.job_id != *job_id {
                    continue;
                }
                let file_fd =
                    match fs::openat(dir.fd, &entry, verified::receipt_read_open_flags(), 0) {
                        Ok(file_fd) => file_fd,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(error) => return Err(Error::from(error)),
                    };
                match verified::verify_receipt_on_fd(
                    file_fd.as_fd(),
                    self.receipt_context(bucket, &shard_str, &entry),
                    None,
                ) {
                    Ok(_) => push("receipt", &parsed.common, dir.child(&entry)),
                    Err(verified::VerificationError::Io(message)) => {
                        return Err(Error::IoFailure(message))
                    }
                    Err(_) => {}
                }
            }
            Ok(())
        })?;
        Ok(results)
    }

    fn receipt_context<'a>(
        &'a self,
        bucket: &'a str,
        shard: &'a str,
        filename: &'a str,
    ) -> verified::ReceiptContext<'a> {
        verified::ReceiptContext {
            queue_id: self.format.queue_id(),
            shard_count: self.format.shard_count(),
            terminal_bucket_width_ns: self.format.terminal_bucket_width_ns(),
            max_payload_length: self.format.max_payload_length(),
            bucket,
            shard,
            filename,
        }
    }

    /// The first authenticated dead object for `job_id`, as (directory, name).
    fn find_dead(&self, job_id: &[u8; 16]) -> Result<Option<(OwnedFd, String)>, Error> {
        let Some(snapshot) = self
            .inspect(job_id)?
            .into_iter()
            .find(|s| s.state == "dead")
        else {
            return Ok(None);
        };
        let (dir_rel, name) = snapshot
            .relative_path
            .rsplit_once('/')
            .expect("inspect paths name a file inside a directory");
        let dir_fd = open_relative(self.root_fd.as_fd(), dir_rel).map_err(Error::from)?;
        Ok(Some((dir_fd, name.to_string())))
    }

    /// Export a dead job's raw bytes to a new output file. Opens the job
    /// through the root capability with O_NOFOLLOW, not via a pathname.
    /// `Ok(None)` means no dead object exists for the job.
    pub fn export_dead(
        &self,
        job_id: &[u8; 16],
        output: &std::path::Path,
    ) -> Result<Option<u64>, Error> {
        let Some((dir_fd, name)) = self.find_dead(job_id)? else {
            return Ok(None);
        };
        let file_fd = match fs::openat(dir_fd.as_fd(), &name, raw_read_open_flags(), 0) {
            Ok(fd) => fd,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(Error::from(error)),
        };
        copy_file_to_path(file_fd.as_fd(), output)
            .map(Some)
            .map_err(regular_open_error)
    }

    /// List every dead object whose name parses and whose tag authenticates
    /// under its bucket and shard. An unreadable directory is an error, not
    /// an empty list.
    pub fn list_dead(&self) -> Result<Vec<Snapshot>, Error> {
        let queue_id = self.format.queue_id();
        let dead_fd = fs::open_directory(self.root_fd.as_fd(), "dead").map_err(Error::from)?;
        let mut out = Vec::new();
        for bucket in fs::read_dir_entries(dead_fd.as_fd()).map_err(Error::from)? {
            let Some(bucket) = bucket.as_ascii_str() else {
                continue;
            };
            let Some(bucket_fd) = open_child_dir(dead_fd.as_fd(), bucket)? else {
                continue;
            };
            for shard in fs::read_dir_entries(bucket_fd.as_fd()).map_err(Error::from)? {
                let Some(shard) = shard.as_ascii_str() else {
                    continue;
                };
                let Some(shard_num) = steadq_names::shard_from_hex(shard) else {
                    continue;
                };
                let Some(shard_fd) = open_child_dir(bucket_fd.as_fd(), shard)? else {
                    continue;
                };
                for entry in fs::read_dir_entries(shard_fd.as_fd()).map_err(Error::from)? {
                    let Some(entry) = entry.as_ascii_str() else {
                        continue;
                    };
                    let Ok(parsed) = steadq_names::parse_dead(entry) else {
                        continue;
                    };
                    if !parsed.authenticate_tag(queue_id, bucket, shard) {
                        continue;
                    }
                    out.push(Snapshot {
                        job_id: parsed.common.job_id,
                        state: "dead".into(),
                        generation: parsed.common.generation,
                        attempt: parsed.common.attempt,
                        maximum_attempts: parsed.common.maximum_attempts,
                        shard: shard_num,
                        relative_path: format!("dead/{bucket}/{shard}/{entry}"),
                        size: 0,
                    });
                }
            }
        }
        out.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
        Ok(out)
    }

    /// Remove a dead job through the phase-aware unlink executor.
    /// `Ok(false)` means no dead object exists for the job.
    pub fn remove_dead(&self, job_id: &[u8; 16]) -> Result<bool, Error> {
        let Some((dir_fd, name)) = self.find_dead(job_id)? else {
            return Ok(false);
        };
        match engine::unlink_verified(dir_fd.as_fd(), &name) {
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
    #[cfg(test)]
    pub(crate) fn check_duplicate_ack(&self, lease: &LeaseInfo) -> AckOutcome {
        match self.authenticated_wall_floor() {
            Ok(wall_floor) => self.duplicate_ack_outcome(lease, wall_floor),
            Err(error) => AckOutcome::NotCommitted(error),
        }
    }

    /// The outcome of acknowledging a lease whose source is gone.
    pub(super) fn duplicate_ack_outcome(
        &self,
        lease: &LeaseInfo,
        wall_floor: WallFloor,
    ) -> AckOutcome {
        match self.check_duplicate_ack_bounded(lease, wall_floor) {
            Ok(true) => AckOutcome::AlreadyAcked,
            Ok(false) => AckOutcome::LeaseLost,
            Err(error) => AckOutcome::NotCommitted(error),
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
        let (file_fd, stat) = open_regular_read(dir_fd, name).map_err(regular_open_error)?;

        // Link count
        if stat.st_nlink != 1 {
            return Err(Error::QueueCorrupt(format!(
                "{name}: unexpected link count {}",
                stat.st_nlink
            )));
        }

        // Use central verifier for header, extension, envelope, and size.
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

    /// Bounded duplicate-ack check. Only a missing receipt directory or
    /// receipt is absence; any other failure is an error, never a definite
    /// "not acknowledged".
    pub(super) fn check_duplicate_ack_bounded(
        &self,
        lease: &LeaseInfo,
        wall_floor: WallFloor,
    ) -> Result<bool, Error> {
        let retention = self.options.receipt_retention_ns;
        let width = self.format.terminal_bucket_width_ns();
        let now_bucket = match steadq_math::bucket_number(wall_floor.unix_ns(), width) {
            Some(bucket) => bucket,
            None => return Ok(false),
        };
        let retention_buckets = match steadq_math::ceiling_bucket(retention, width) {
            Some(buckets) => buckets,
            None => return Ok(false),
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
            return Ok(false);
        };
        let expected = verified::ExpectedReceipt {
            common: receipt_common.clone(),
            token: lease.token,
            envelope_digest: lease.envelope_digest,
            payload_length: lease.payload_length,
        };
        let absent = |error: &std::io::Error| error.kind() == std::io::ErrorKind::NotFound;
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
            let dir_fd = match open_relative(self.root_fd.as_fd(), &receipt_dir) {
                Ok(fd) => fd,
                Err(error) if absent(&error) => continue,
                Err(error) => return Err(Error::from(error)),
            };
            let file_fd = match fs::openat(
                dir_fd.as_fd(),
                &receipt_name,
                verified::receipt_read_open_flags(),
                0,
            ) {
                Ok(fd) => fd,
                Err(error) if absent(&error) => continue,
                Err(error) => return Err(Error::from(error)),
            };
            // A receipt that does not verify as strict evidence is not a
            // duplicate; only a failed read leaves the answer unknown.
            match verified::verify_receipt_on_fd(
                file_fd.as_fd(),
                self.receipt_context(&bucket_str, &shard_str, &receipt_name),
                Some(&expected),
            ) {
                Ok(_) => return Ok(true),
                Err(verified::VerificationError::Io(message)) => {
                    return Err(Error::IoFailure(message))
                }
                Err(_) => {}
            }
        }
        Ok(false)
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

/// Open a child directory for a listing. A child that vanished or is not
/// a directory is skipped; any other failure is the caller's error.
fn open_child_dir(parent: BorrowedFd<'_>, name: &str) -> Result<Option<OwnedFd>, Error> {
    match fs::open_directory(parent, name) {
        Ok(fd) => Ok(Some(fd)),
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                || error.raw_os_error() == Some(libc::ENOTDIR) =>
        {
            Ok(None)
        }
        Err(error) => Err(Error::from(error)),
    }
}

/// A shard directory found by `visit_shard_dirs`.
struct ShardDir<'a> {
    fd: BorrowedFd<'a>,
    path: &'a str,
}

impl ShardDir<'_> {
    fn child(&self, name: &str) -> String {
        format!("{}/{name}", self.path)
    }
}

/// ASCII entry names of a directory; other names are not protocol names.
fn names_in(dir: BorrowedFd<'_>) -> Result<Vec<String>, Error> {
    Ok(fs::read_dir_entries(dir)
        .map_err(Error::from)?
        .iter()
        .filter_map(|entry| entry.as_ascii_str().map(str::to_owned))
        .collect())
}

/// Call `visit` for every `<state>/<level>.../<shard>` directory `depth`
/// levels below `state`, with the name of the last level (the bucket).
/// Directories that vanish or are not directories are skipped.
fn visit_shard_dirs(
    root: BorrowedFd<'_>,
    state: &str,
    depth: usize,
    shard: &str,
    visit: &mut dyn FnMut(ShardDir<'_>, &str) -> Result<(), Error>,
) -> Result<(), Error> {
    fn walk(
        parent: BorrowedFd<'_>,
        path: &str,
        last: &str,
        depth: usize,
        shard: &str,
        visit: &mut dyn FnMut(ShardDir<'_>, &str) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if depth == 0 {
            if let Some(fd) = open_child_dir(parent, shard)? {
                let path = format!("{path}/{shard}");
                visit(
                    ShardDir {
                        fd: fd.as_fd(),
                        path: &path,
                    },
                    last,
                )?;
            }
            return Ok(());
        }
        for name in names_in(parent)? {
            if let Some(child) = open_child_dir(parent, &name)? {
                walk(
                    child.as_fd(),
                    &format!("{path}/{name}"),
                    &name,
                    depth - 1,
                    shard,
                    visit,
                )?;
            }
        }
        Ok(())
    }
    match open_child_dir(root, state)? {
        Some(fd) => walk(fd.as_fd(), state, state, depth, shard, visit),
        None => Ok(()),
    }
}

/// Read-only open of an object by name: never through a symlink, never
/// blocking on a FIFO, never inherited by a child process.
pub(crate) fn raw_read_open_flags() -> i32 {
    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK
}

/// Open `name` under `dir_fd` for reading and require a regular file. A
/// symlink or any other file type is `InvalidData`; see `regular_open_error`.
pub(crate) fn open_regular_read(
    dir_fd: BorrowedFd<'_>,
    name: &str,
) -> std::io::Result<(OwnedFd, libc::stat)> {
    let not_regular = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{name}: not a regular file"),
        )
    };
    let fd = fs::openat(dir_fd, name, raw_read_open_flags(), 0).map_err(|error| {
        if error.raw_os_error() == Some(libc::ELOOP) {
            not_regular()
        } else {
            error
        }
    })?;
    let stat = fs::fstat(fd.as_fd())?;
    if !is_regular(&stat) {
        return Err(not_regular());
    }
    Ok((fd, stat))
}

/// A file that is not regular is corruption; anything else is I/O.
pub(crate) fn regular_open_error(error: std::io::Error) -> Error {
    if error.kind() == std::io::ErrorKind::InvalidData {
        Error::QueueCorrupt(error.to_string())
    } else {
        Error::from(error)
    }
}

fn is_regular(stat: &libc::stat) -> bool {
    stat.st_mode & libc::S_IFMT == libc::S_IFREG
}

/// Copy the regular file behind `file_fd` to `output`, which must not
/// exist yet, not even as a symlink, and sync it. Returns the bytes written.
pub(crate) fn copy_file_to_path(
    file_fd: BorrowedFd<'_>,
    output: &std::path::Path,
) -> std::io::Result<u64> {
    if !is_regular(&fs::fstat(file_fd)?) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "export source is not a regular file",
        ));
    }
    let mut source = std::fs::File::from(file_fd.try_clone_to_owned()?);
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    let written = std::io::copy(&mut source, &mut out)?;
    out.sync_all()?;
    Ok(written)
}
