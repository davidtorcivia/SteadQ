// Ack, retry, bury, renew, and leased-source moves.
use super::*;

impl Queue {
    /// Acknowledge a lease: strictly verify its payload, then move it to a
    /// terminal receipt.
    ///
    /// The payload is re-hashed at acknowledgment time to close the TOCTOU
    /// window between lease delivery and terminal publication. SteadQ/1 has no
    /// public unverified acknowledgment path.
    pub fn ack(&mut self, lease: &LeaseInfo) -> AckOutcome {
        self.ack_inner_with_dirty(lease, None)
    }

    pub(super) fn ack_batched(
        &mut self,
        lease: &LeaseInfo,
        dirty: &mut engine::DirtySet,
    ) -> AckOutcome {
        self.ack_inner_with_dirty(lease, Some(dirty))
    }

    pub(super) fn ack_inner_with_dirty(
        &mut self,
        lease: &LeaseInfo,
        mut dirty: Option<&mut engine::DirtySet>,
    ) -> AckOutcome {
        if let Err(e) = self.check_not_poisoned() {
            return AckOutcome::NotCommitted(e);
        }

        // Use effective wall floor for terminal transitions
        let wall_floor = match self.wall_floor_for_mutation() {
            Ok(floor) => floor,
            Err(e) => return AckOutcome::NotCommitted(e),
        };
        let receipt_common =
            match next_identity(ProtocolOperation::Acknowledge, &lease_common(lease)) {
                Ok(common) => common,
                Err(error) => return AckOutcome::NotCommitted(error),
            };

        let terminal_bucket =
            match bucket_number(wall_floor.unix_ns(), self.format.terminal_bucket_width_ns()) {
                Some(bucket) => bucket,
                None => return AckOutcome::NotCommitted(Error::StateExhausted),
            };
        let target =
            self.layout()
                .receipt_in_bucket(&receipt_common, &lease.token, terminal_bucket);
        let receipt_dir = target.directory();
        let receipt_name = target.filename;
        let transition_ticket = match self.transition_ticket_for_lease(
            lease,
            TransitionOperation::Acknowledge,
            TicketDestination::Receipt { terminal_bucket },
        ) {
            Ok(ticket) => ticket,
            Err(error) => return AckOutcome::NotCommitted(error),
        };
        if let Err(e) = self.ensure_dir_with_dirty(&receipt_dir, dirty.as_deref_mut()) {
            return AckOutcome::NotCommitted(Error::from(e));
        }

        let receipt_dir_fd = match open_relative(self.root_fd.as_fd(), &receipt_dir) {
            Ok(fd) => fd,
            Err(e) => return AckOutcome::NotCommitted(Error::from(e)),
        };

        // Validate the current lease source before acknowledging
        let source = match self.open_and_validate_current_lease(lease) {
            Ok(Some(source)) => source,
            Ok(None) => {
                // Source is gone. Before returning LeaseLost,
                // check if this was a duplicate ack by probing receipts.
                if self.check_duplicate_ack_bounded(lease, wall_floor) {
                    return AckOutcome::AlreadyAcked;
                }
                return AckOutcome::LeaseLost;
            }
            Err(Error::QueueCorrupt(e)) => {
                self.poison();
                return AckOutcome::NotCommitted(Error::QueueCorrupt(e));
            }
            Err(e) => return AckOutcome::NotCommitted(e),
        };

        if let Err(e) = self.verify_payload_on_fd(source.file_fd.as_fd()) {
            self.poison();
            return AckOutcome::NotCommitted(e);
        }

        match Self::execute_leased_move_with_dirty(
            &source,
            receipt_dir_fd.as_fd(),
            &receipt_name,
            dirty,
        ) {
            LeasedMoveOutcome::Committed => AckOutcome::Acked,
            LeasedMoveOutcome::OutcomeUnknown(phase) => {
                self.poison();
                AckOutcome::OutcomeUnknown(transition_ticket.with_phase(phase))
            }
            LeasedMoveOutcome::Collision => {
                // Authenticate the existing receipt instead of blindly
                // reporting AlreadyAcked. A conflicting object at the
                // deterministic path must not be treated as idempotent success.
                if self.receipt_is_authentic(lease, &receipt_dir, &receipt_name) {
                    // Source exists and receipt is authentic: both observed.
                    // The lease is still live. Report as corruption rather
                    // than collapsing into idempotent success.
                    self.poison();
                    AckOutcome::NotCommitted(Error::QueueCorrupt(
                        "source lease and receipt both exist".into(),
                    ))
                } else {
                    self.poison();
                    AckOutcome::NotCommitted(Error::QueueCorrupt(
                        "conflicting object at receipt path".into(),
                    ))
                }
            }
            LeasedMoveOutcome::SourceGone => {
                // On source absence, do a bounded receipt probe.
                // Construct the finite set of exact retained receipt paths
                // and check them directly (bounded, not full scan).
                if self.check_duplicate_ack_bounded(lease, wall_floor) {
                    AckOutcome::AlreadyAcked
                } else {
                    AckOutcome::LeaseLost
                }
            }
            LeasedMoveOutcome::SourceChanged => {
                self.poison();
                AckOutcome::NotCommitted(Error::QueueCorrupt(
                    "leased source identity changed before acknowledgment".into(),
                ))
            }
            LeasedMoveOutcome::Failed(error) => AckOutcome::NotCommitted(error),
        }
    }

    /// Retry a lease immediately (move to ready).
    pub fn retry_now(&mut self, lease: &LeaseInfo) -> TransitionOutcome {
        self.retry(lease, RetryTiming::Immediate)
    }

    /// Retry a lease at a future time (move to delayed).
    pub fn retry_at(&mut self, lease: &LeaseInfo, not_before_ns: u64) -> TransitionOutcome {
        let wall_floor = match self.wall_floor_for_mutation() {
            Ok(floor) => floor,
            Err(error) => return TransitionOutcome::NotCommitted(error),
        };
        self.retry(
            lease,
            RetryTiming::Delayed {
                not_before_ns,
                wall_floor,
            },
        )
    }

    /// Retry a lease after a duration.
    pub fn retry_after(&mut self, lease: &LeaseInfo, duration_ns: u64) -> TransitionOutcome {
        let wall_floor = match self.wall_floor_for_mutation() {
            Ok(floor) => floor,
            Err(e) => return TransitionOutcome::NotCommitted(e),
        };
        let deadline = match steadq_math::retry_wall_deadline(wall_floor.unix_ns(), duration_ns) {
            Some(d) => d,
            None => {
                return TransitionOutcome::NotCommitted(Error::InvalidInput(
                    "deadline overflow".into(),
                ))
            }
        };
        self.retry(
            lease,
            RetryTiming::Delayed {
                not_before_ns: deadline,
                wall_floor,
            },
        )
    }

    /// Retry with a policy (computes delay from attempt and policy).
    pub fn retry_with_policy(
        &mut self,
        lease: &LeaseInfo,
        policy: &steadq_math::RetryPolicy,
    ) -> TransitionOutcome {
        if let Err(e) = policy.validate() {
            return TransitionOutcome::NotCommitted(Error::InvalidInput(e.to_string()));
        }

        let delay_ms = match steadq_math::retry_delay_ms(
            self.format.queue_id(),
            &lease.job_id,
            lease.attempt,
            policy,
        ) {
            Ok(d) => d,
            Err(e) => return TransitionOutcome::NotCommitted(Error::InvalidInput(e.to_string())),
        };

        if delay_ms == 0 {
            self.retry_now(lease)
        } else {
            let delay_ns = match steadq_math::checked_mul_u64(delay_ms, 1_000_000) {
                Some(d) => d,
                None => {
                    return TransitionOutcome::NotCommitted(Error::InvalidInput(
                        "delay overflow".into(),
                    ))
                }
            };
            let wall_floor = match self.wall_floor_for_mutation() {
                Ok(floor) => floor,
                Err(e) => return TransitionOutcome::NotCommitted(e),
            };
            let deadline = match steadq_math::retry_wall_deadline(wall_floor.unix_ns(), delay_ns) {
                Some(d) => d,
                None => {
                    return TransitionOutcome::NotCommitted(Error::InvalidInput(
                        "deadline overflow".into(),
                    ))
                }
            };
            self.retry(
                lease,
                RetryTiming::Delayed {
                    not_before_ns: deadline,
                    wall_floor,
                },
            )
        }
    }

    fn retry(&mut self, lease: &LeaseInfo, timing: RetryTiming) -> TransitionOutcome {
        if let Err(e) = self.check_not_poisoned() {
            return TransitionOutcome::NotCommitted(e);
        }
        // If delayed target is at or before the effective wall floor, it's retry_now.
        let (delayed_ns, wall_floor) = match timing {
            RetryTiming::Immediate => (None, None),
            RetryTiming::Delayed {
                not_before_ns,
                wall_floor,
            } if not_before_ns <= wall_floor.unix_ns() => (None, Some(wall_floor)),
            RetryTiming::Delayed {
                not_before_ns,
                wall_floor,
            } => (Some(not_before_ns), Some(wall_floor)),
        };

        // Check attempt limit for retry
        if lease.attempt >= lease.maximum_attempts {
            let wall_floor = match wall_floor {
                Some(floor) => floor,
                None => match self.wall_floor_for_mutation() {
                    Ok(floor) => floor,
                    Err(error) => return TransitionOutcome::NotCommitted(error),
                },
            };
            // Move to dead with attempts_exhausted
            return match self.bury_with_wall_floor(lease, DeadReason::AttemptsExhausted, wall_floor)
            {
                TransitionOutcome::Committed => TransitionOutcome::Committed,
                other => other,
            };
        }

        let (dest_dir, dest_name, operation, destination) = match delayed_ns {
            Some(nb) => {
                let common =
                    match next_identity(ProtocolOperation::RetryLater, &lease_common(lease)) {
                        Ok(common) => common,
                        Err(error) => return TransitionOutcome::NotCommitted(error),
                    };
                let target = match self.layout().delayed(&common, nb) {
                    Ok(target) => target,
                    Err(error) => return TransitionOutcome::NotCommitted(error),
                };
                (
                    target.directory(),
                    target.filename,
                    TransitionOperation::RetryLater,
                    TicketDestination::Delayed { not_before_ns: nb },
                )
            }
            None => {
                let common = match next_identity(ProtocolOperation::RetryNow, &lease_common(lease))
                {
                    Ok(common) => common,
                    Err(error) => return TransitionOutcome::NotCommitted(error),
                };
                let target = self.layout().ready(&common);
                (
                    target.directory(),
                    target.filename,
                    TransitionOperation::RetryNow,
                    TicketDestination::Ready {},
                )
            }
        };

        let ticket = match self.transition_ticket_for_lease(lease, operation, destination) {
            Ok(ticket) => ticket,
            Err(error) => return TransitionOutcome::NotCommitted(error),
        };
        self.move_leased(lease, &dest_dir, &dest_name, &ticket)
    }

    /// Bury a lease (move to dead).
    pub fn bury(&mut self, lease: &LeaseInfo, reason: DeadReason) -> TransitionOutcome {
        if let Err(e) = self.check_not_poisoned() {
            return TransitionOutcome::NotCommitted(e);
        }
        self.bury_internal(lease, reason)
    }

    fn bury_internal(&mut self, lease: &LeaseInfo, reason: DeadReason) -> TransitionOutcome {
        let wall_floor = match self.wall_floor_for_mutation() {
            Ok(floor) => floor,
            Err(error) => return TransitionOutcome::NotCommitted(error),
        };
        self.bury_with_wall_floor(lease, reason, wall_floor)
    }

    fn bury_with_wall_floor(
        &mut self,
        lease: &LeaseInfo,
        reason: DeadReason,
        wall_floor: WallFloor,
    ) -> TransitionOutcome {
        let common = match next_identity(ProtocolOperation::Bury, &lease_common(lease)) {
            Ok(common) => common,
            Err(error) => return TransitionOutcome::NotCommitted(error),
        };

        let terminal_bucket =
            match bucket_number(wall_floor.unix_ns(), self.format.terminal_bucket_width_ns()) {
                Some(bucket) => bucket,
                None => return TransitionOutcome::NotCommitted(Error::StateExhausted),
            };
        let target = self
            .layout()
            .dead_in_bucket(&common, reason as u16, terminal_bucket);
        let dest_dir = target.directory();
        let fname = target.filename;
        let ticket = match self.transition_ticket_for_lease(
            lease,
            TransitionOperation::Bury,
            TicketDestination::Dead {
                terminal_bucket,
                reason: reason as u16,
            },
        ) {
            Ok(ticket) => ticket,
            Err(error) => return TransitionOutcome::NotCommitted(error),
        };

        self.move_leased(lease, &dest_dir, &fname, &ticket)
    }

    /// Renew a lease with a new deadline.
    pub fn renew(&mut self, lease: &LeaseInfo, lease_duration_ns: u64) -> RenewOutcome {
        if self.deferred_dir_sync {
            let mut tmp = self.dirty.replace(engine::DirtySet::new());
            let outcome = self.renew_with_dirty(lease, lease_duration_ns, Some(&mut tmp));
            let prev = self.dirty.replace(tmp);
            drop(prev);
            return match outcome {
                RenewOutcome::Renewed(info) => RenewOutcome::Deferred(info),
                outcome => outcome,
            };
        }
        self.renew_with_dirty(lease, lease_duration_ns, None)
    }

    fn renew_with_dirty(
        &mut self,
        lease: &LeaseInfo,
        lease_duration_ns: u64,
        dirty: Option<&mut engine::DirtySet>,
    ) -> RenewOutcome {
        if let Err(e) = self.check_not_poisoned() {
            return RenewOutcome::NotCommitted(e);
        }

        if !lease_duration_is_valid(lease_duration_ns) {
            return RenewOutcome::NotCommitted(Error::InvalidInput(
                "lease duration must be 1s to 7d".into(),
            ));
        }

        let boottime_now = match fs::clock_boottime_ns() {
            Ok(t) => t,
            Err(e) => return RenewOutcome::NotCommitted(Error::from(e)),
        };
        let wall_now = match self.wall_floor_for_mutation() {
            Ok(floor) => floor.unix_ns(),
            Err(e) => return RenewOutcome::NotCommitted(e),
        };
        let new_boottime_dl = match boottime_now.checked_add(lease_duration_ns) {
            Some(d) => d,
            None => {
                return RenewOutcome::NotCommitted(Error::InvalidInput("deadline overflow".into()))
            }
        };
        let new_wall_dl = match wall_now.checked_add(lease_duration_ns) {
            Some(d) => d,
            None => {
                return RenewOutcome::NotCommitted(Error::InvalidInput("deadline overflow".into()))
            }
        };
        let common = match next_identity(ProtocolOperation::Renew, &lease_common(lease)) {
            Ok(common) => common,
            Err(error) => return RenewOutcome::NotCommitted(error),
        };
        let new_gen = common.generation;

        let target = match self
            .layout()
            .leased(&common, new_boottime_dl, new_wall_dl, &lease.token)
        {
            Ok(target) => target,
            Err(error) => return RenewOutcome::NotCommitted(error),
        };
        let dest_dir = target.directory();
        let fname = target.filename;

        let ticket = match self.transition_ticket_for_lease(
            lease,
            TransitionOperation::Renew,
            TicketDestination::Leased {
                boot_id: self.boot_id.clone(),
                boottime_deadline_ns: new_boottime_dl,
                wall_deadline_ns: new_wall_dl,
            },
        ) {
            Ok(ticket) => ticket,
            Err(error) => return RenewOutcome::NotCommitted(error),
        };

        match self.move_leased_with_dirty(lease, &dest_dir, &fname, &ticket, dirty) {
            TransitionOutcome::Committed => RenewOutcome::Renewed(LeaseInfo {
                generation: new_gen,
                expires_boottime_ns: new_boottime_dl,
                expires_wall_ns: new_wall_dl,
                exact_source_path: format!("{dest_dir}/{fname}"),
                ..lease.clone()
            }),
            TransitionOutcome::LeaseLost => RenewOutcome::LeaseLost,
            TransitionOutcome::NotCommitted(e) => RenewOutcome::NotCommitted(e),
            TransitionOutcome::OutcomeUnknown(t) => RenewOutcome::OutcomeUnknown(t),
        }
    }

    /// Open and validate the current leased source object.
    /// Validates the source path, filename, header, and identity against the handle.
    pub(super) fn is_expected_dev_zero(dev: u64) -> bool {
        dev == 0
    }

    pub(super) fn is_expected_inode_zero(ino: u64) -> bool {
        ino == 0
    }

    pub(super) fn shard_matches(path: u32, computed: u32) -> bool {
        path == computed
    }

    /// Returns a retained source descriptor and exact path identity on success.
    pub(super) fn open_and_validate_current_lease(
        &self,
        lease: &LeaseInfo,
    ) -> Result<Option<LeasedSourceWitness>, Error> {
        if Self::is_expected_dev_zero(lease.expected_dev) {
            return Err(Error::QueueCorrupt(
                "expected_dev is zero (forgeable handle)".into(),
            ));
        }
        if Self::is_expected_inode_zero(lease.expected_inode) {
            return Err(Error::QueueCorrupt(
                "expected_inode is zero (forgeable handle)".into(),
            ));
        }

        let (loc, src_name) = self.layout().parse_leased_path(&lease.exact_source_path)?;
        let (boot_id, path_bucket, path_shard) = match &loc {
            layout::Location::Leased {
                boot_id,
                bucket,
                shard,
            } => (boot_id.clone(), *bucket, *shard),
            _ => unreachable!("parse_leased_path always returns Leased"),
        };

        if boot_id != self.boot_id {
            return Err(Error::InvalidInput(format!(
                "source boot_id '{}' does not match queue boot_id '{}'",
                boot_id, self.boot_id
            )));
        }
        if boot_id != lease.boot_id {
            return Err(Error::QueueCorrupt(
                "source boot_id does not match lease handle".into(),
            ));
        }

        let computed_shard = compute_shard(
            self.format.queue_id(),
            &lease.job_id,
            self.format.shard_count(),
        );
        if !Self::shard_matches(path_shard, computed_shard) {
            return Err(Error::QueueCorrupt(format!(
                "source shard {path_shard} does not match queue-derived shard {computed_shard}"
            )));
        }

        let src_dir = lease
            .exact_source_path
            .rsplit_once('/')
            .map(|(directory, _)| directory.to_string())
            .ok_or_else(|| Error::QueueCorrupt("invalid leased path".into()))?;

        // Only ENOENT means "source gone". Other errors are real failures.
        let src_dir_fd = match open_relative(self.root_fd.as_fd(), &src_dir) {
            Ok(fd) => fd,
            Err(error) => match classify_lease_directory_open_failure(&error) {
                LeaseDirectoryOpenFailure::Gone => return Ok(None),
                LeaseDirectoryOpenFailure::InvalidDirectory => {
                    return Err(Error::QueueCorrupt(
                        "intermediate lease path component is not a directory".into(),
                    ));
                }
                LeaseDirectoryOpenFailure::Io => {
                    return Err(Error::from(error));
                }
            },
        };

        let src_stat = match fs::fstatat(src_dir_fd.as_fd(), &src_name) {
            Ok(s) => s,
            Err(error) => match classify_presence_failure(&error) {
                PresenceFailure::Absent => return Ok(None),
                PresenceFailure::Io => return Err(Error::from(error)),
            },
        };

        if !is_singly_linked_regular(src_stat.st_mode, src_stat.st_nlink) {
            return Err(Error::QueueCorrupt(
                "source is not a singly-linked regular file".into(),
            ));
        }

        let parsed = steadq_names::parse_leased(&src_name).map_err(|_| {
            Error::QueueCorrupt("source filename is not a valid leased name".into())
        })?;

        if parsed.common.job_id != lease.job_id {
            return Err(Error::QueueCorrupt("source job_id mismatch".into()));
        }
        if parsed.common.generation != lease.generation {
            return Err(Error::QueueCorrupt("source generation mismatch".into()));
        }
        if parsed.common.attempt != lease.attempt {
            return Err(Error::QueueCorrupt("source attempt mismatch".into()));
        }
        if parsed.common.maximum_attempts != lease.maximum_attempts {
            return Err(Error::QueueCorrupt("source max_attempts mismatch".into()));
        }
        if parsed.token != lease.token {
            return Err(Error::QueueCorrupt("source token mismatch".into()));
        }
        if parsed.boottime_deadline_ns != lease.expires_boottime_ns {
            return Err(Error::QueueCorrupt(
                "source boottime deadline mismatch".into(),
            ));
        }
        if parsed.wall_deadline_ns != lease.expires_wall_ns {
            return Err(Error::QueueCorrupt("source wall deadline mismatch".into()));
        }
        let expected_bucket = steadq_math::lease_bucket(
            parsed.boottime_deadline_ns,
            self.format.lease_bucket_width_ns(),
        )
        .ok_or(Error::StateExhausted)?;
        if path_bucket != expected_bucket {
            return Err(Error::QueueCorrupt("source lease bucket mismatch".into()));
        }
        if !parsed.authenticate_tag(
            self.format.queue_id(),
            &boot_id,
            &bucket_hex(path_bucket),
            &shard_hex(path_shard),
        ) {
            return Err(Error::QueueCorrupt("source name tag mismatch".into()));
        }

        let file_fd = fs::openat(src_dir_fd.as_fd(), &src_name, resolver_file_open_flags(), 0)
            .map_err(Error::from)?;
        let opened_stat = fs::fstat(file_fd.as_fd()).map_err(Error::from)?;
        if !stat_matches_witness(&opened_stat, lease.expected_dev, lease.expected_inode) {
            return Err(Error::QueueCorrupt(
                "opened source identity does not match lease handle".into(),
            ));
        }
        if !stat_matches_witness(
            &src_stat,
            opened_stat.st_dev as u64,
            opened_stat.st_ino as u64,
        ) {
            return Err(Error::QueueCorrupt(
                "source path changed while opening lease".into(),
            ));
        }
        let mut header_buf = [0u8; 128];
        fs::pread_exact(file_fd.as_fd(), &mut header_buf, 0).map_err(Error::from)?;
        let header = FixedHeader::decode(&header_buf)
            .map_err(|e| Error::QueueCorrupt(format!("header decode: {e}")))?;

        if header.job_id != lease.job_id {
            return Err(Error::QueueCorrupt(
                "header job_id does not match handle".into(),
            ));
        }

        // Verify header maximum_attempts matches filename/handle
        if header.maximum_attempts != lease.maximum_attempts {
            return Err(Error::QueueCorrupt(format!(
                "header maximum_attempts {} does not match handle {}",
                header.maximum_attempts, lease.maximum_attempts
            )));
        }

        // Verify envelope digest matches the handle
        if header.envelope_digest != lease.envelope_digest {
            return Err(Error::QueueCorrupt(
                "envelope digest does not match handle".into(),
            ));
        }
        if header.payload_length != lease.payload_length {
            return Err(Error::QueueCorrupt(
                "payload length does not match handle".into(),
            ));
        }
        if header.payload_digest != lease.payload_digest {
            return Err(Error::QueueCorrupt(
                "payload digest does not match handle".into(),
            ));
        }

        // Extension read failure is a real error, not a silent pass.
        let ext_len = header.extension_header_length as usize;
        if verified::is_extension_too_large(ext_len) {
            return Err(Error::QueueCorrupt("extension header too large".into()));
        }
        // Always verify envelope digest (even when extension is empty).
        let mut ext_buf = vec![0u8; ext_len];
        if verified::is_extension_present(ext_len) {
            fs::pread_exact(file_fd.as_fd(), &mut ext_buf, 128).map_err(Error::from)?;
        }
        if !steadq_format::verify_envelope_digest(&header, &ext_buf) {
            return Err(Error::QueueCorrupt("envelope digest mismatch".into()));
        }

        // Verify exact file size (no trailing data)
        if opened_stat.st_size < 0 {
            return Err(Error::QueueCorrupt("negative file size".into()));
        }
        let expected_size = 128u64
            .checked_add(ext_len as u64)
            .and_then(|s| s.checked_add(header.payload_length))
            .ok_or_else(|| Error::QueueCorrupt("size overflow".into()))?;
        if opened_stat.st_size as u64 != expected_size {
            return Err(Error::QueueCorrupt(format!(
                "source file size mismatch: expected {}, got {}",
                expected_size, opened_stat.st_size
            )));
        }

        Ok(Some(LeasedSourceWitness {
            directory_fd: src_dir_fd,
            name: src_name,
            file_fd,
            device: opened_stat.st_dev as u64,
            inode: opened_stat.st_ino as u64,
        }))
    }

    pub(super) fn observe_leased_source_path(
        source: &LeasedSourceWitness,
    ) -> Result<WitnessPathObservation, Error> {
        observe_witness_path(
            source.directory_fd.as_fd(),
            &source.name,
            source.device,
            source.inode,
        )
    }

    pub(super) fn execute_leased_move_with_dirty(
        source: &LeasedSourceWitness,
        destination_directory_fd: BorrowedFd<'_>,
        destination_name: &str,
        dirty: Option<&mut engine::DirtySet>,
    ) -> LeasedMoveOutcome {
        match Self::observe_leased_source_path(source) {
            Ok(WitnessPathObservation::Match) => {}
            Ok(WitnessPathObservation::Gone) => return LeasedMoveOutcome::SourceGone,
            Ok(WitnessPathObservation::Mismatch) => {
                return LeasedMoveOutcome::SourceChanged;
            }
            Err(error) => return LeasedMoveOutcome::Failed(error),
        }

        let result = match &dirty {
            Some(_) => engine::move_witnessed_noreplace_deferred(
                source.directory_fd.as_fd(),
                &source.name,
                destination_directory_fd,
                destination_name,
                engine::MoveIdentity::new(source.device, source.inode),
                |_| Ok(()),
            )
            .map(|_| ()),
            None => engine::move_witnessed_noreplace(
                source.directory_fd.as_fd(),
                &source.name,
                destination_directory_fd,
                destination_name,
                engine::MoveIdentity::new(source.device, source.inode),
            ),
        };
        let outcome = match result {
            Ok(()) => LeasedMoveOutcome::Committed,
            Err(engine::MoveFailure::SourceMissing) => LeasedMoveOutcome::SourceGone,
            Err(engine::MoveFailure::AlreadyExists) => LeasedMoveOutcome::Collision,
            Err(engine::MoveFailure::NotCommitted { source, .. }) => {
                LeasedMoveOutcome::Failed(Error::from(source))
            }
            Err(engine::MoveFailure::OutcomeUnknown { phase, .. }) => {
                LeasedMoveOutcome::OutcomeUnknown(ticket_phase_for_move_outcome_unknown(phase))
            }
        };
        if matches!(outcome, LeasedMoveOutcome::Committed) {
            if let Some(d) = dirty {
                match d
                    .record(source.directory_fd.as_fd())
                    .and_then(|()| d.record(destination_directory_fd))
                {
                    Ok(()) => {}
                    Err(_) => {
                        return LeasedMoveOutcome::OutcomeUnknown(
                            TransitionPhase::DestinationDirectoryDurable,
                        )
                    }
                }
            }
        }
        outcome
    }

    /// Internal: move a leased object to a new state directory.
    pub(super) fn move_leased(
        &mut self,
        lease: &LeaseInfo,
        dest_dir: &str,
        dest_name: &str,
        ticket: &TransitionTicket,
    ) -> TransitionOutcome {
        self.move_leased_with_dirty(lease, dest_dir, dest_name, ticket, None)
    }

    pub(super) fn move_leased_with_dirty(
        &mut self,
        lease: &LeaseInfo,
        dest_dir: &str,
        dest_name: &str,
        ticket: &TransitionTicket,
        mut dirty: Option<&mut engine::DirtySet>,
    ) -> TransitionOutcome {
        if let Err(e) = self.ensure_dir_with_dirty(dest_dir, dirty.as_deref_mut()) {
            return TransitionOutcome::NotCommitted(Error::from(e));
        }

        let dest_dir_fd = match open_relative(self.root_fd.as_fd(), dest_dir) {
            Ok(fd) => fd,
            Err(e) => return TransitionOutcome::NotCommitted(Error::from(e)),
        };

        // Validate the current lease source before transitioning
        let source = match self.open_and_validate_current_lease(lease) {
            Ok(Some(source)) => source,
            Ok(None) => return TransitionOutcome::LeaseLost,
            Err(Error::QueueCorrupt(e)) => {
                self.poison();
                return TransitionOutcome::NotCommitted(Error::QueueCorrupt(e));
            }
            Err(e) => return TransitionOutcome::NotCommitted(e),
        };

        match Self::execute_leased_move_with_dirty(&source, dest_dir_fd.as_fd(), dest_name, dirty) {
            LeasedMoveOutcome::Committed => TransitionOutcome::Committed,
            LeasedMoveOutcome::OutcomeUnknown(phase) => {
                self.poison();
                TransitionOutcome::OutcomeUnknown(ticket.with_phase(phase))
            }
            LeasedMoveOutcome::SourceGone => TransitionOutcome::LeaseLost,
            LeasedMoveOutcome::SourceChanged => {
                self.poison();
                TransitionOutcome::NotCommitted(Error::QueueCorrupt(
                    "leased source identity changed before transition".into(),
                ))
            }
            LeasedMoveOutcome::Collision => {
                TransitionOutcome::NotCommitted(Error::QueueCorrupt("destination exists".into()))
            }
            LeasedMoveOutcome::Failed(error) => TransitionOutcome::NotCommitted(error),
        }
    }

    pub(super) fn transition_ticket_for_lease(
        &self,
        lease: &LeaseInfo,
        operation: TransitionOperation,
        destination: TicketDestination,
    ) -> Result<TransitionTicket, Error> {
        TransitionTicket::new(
            *self.format.queue_id(),
            operation,
            TransitionPhase::Linearized,
            TicketIdentity::new(
                lease.job_id,
                lease.generation,
                lease.attempt,
                lease.maximum_attempts,
                lease.token,
                TicketEvidence::new(lease.envelope_digest, lease.payload_length),
            ),
            TicketSource::Leased {
                boot_id: lease.boot_id.clone(),
                boottime_deadline_ns: lease.expires_boottime_ns,
                wall_deadline_ns: lease.expires_wall_ns,
            },
            destination,
        )
    }
}
