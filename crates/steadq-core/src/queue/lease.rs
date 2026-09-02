// Ready-shard scan, claim, and exhausted-attempt dead-letter.
use super::*;

impl Queue {
    /// Claim a ready job, returning a lease. Empty scans and transient watermark
    /// lock contention retry with bounded exponential backoff until `max_wait_ns`.
    pub fn lease(&mut self, max_wait_ns: u64, lease_duration_ns: u64) -> LeaseOutcome {
        self.lease_inner_with_dirty(max_wait_ns, lease_duration_ns, None)
    }

    pub(super) fn lease_batched(
        &mut self,
        max_wait_ns: u64,
        lease_duration_ns: u64,
        dirty: &mut engine::DirtySet,
    ) -> LeaseOutcome {
        self.lease_inner_with_dirty(max_wait_ns, lease_duration_ns, Some(dirty))
    }

    pub(super) fn lease_inner_with_dirty(
        &mut self,
        max_wait_ns: u64,
        lease_duration_ns: u64,
        mut dirty: Option<&mut engine::DirtySet>,
    ) -> LeaseOutcome {
        let started = std::time::Instant::now();
        let wait = std::time::Duration::from_nanos(max_wait_ns);
        let mut backoff = std::time::Duration::from_micros(50);
        let max_backoff = std::time::Duration::from_millis(10);

        loop {
            let outcome = self.lease_once_with_dirty(lease_duration_ns, dirty.as_deref_mut());
            let retryable = matches!(
                outcome,
                LeaseOutcome::Empty | LeaseOutcome::NotCommitted(Error::MaintenanceBusy)
            );
            if max_wait_ns == 0 || !retryable {
                return outcome;
            }

            let elapsed = started.elapsed();
            if elapsed >= wait {
                return outcome;
            }
            let nap = backoff.min(wait.saturating_sub(elapsed));
            // An event in a ready shard cuts the nap short; the scan is
            // still the only source of truth, and the backoff schedule
            // grows identically so the scan-rate bound is unchanged.
            if let Some(fd) = self.ready_watch.as_ref() {
                if fs::inotify::wait_readable(fd.as_fd(), nap).is_err() {
                    self.ready_watch = None;
                    std::thread::sleep(nap);
                }
            } else {
                self.ensure_ready_watch();
                std::thread::sleep(nap);
            }
            backoff = backoff.saturating_mul(2).min(max_backoff);
        }
    }

    /// Establish the ready-shard watch once. Any failure is permanent for
    /// this handle: the wait loop falls back to plain sleeps.
    pub(super) fn ensure_ready_watch(&mut self) {
        if self.ready_watch_attempted {
            return;
        }
        self.ready_watch_attempted = true;
        let Ok(fd) = fs::inotify::init() else {
            return;
        };
        let ready = self.root_path.join("ready");
        let count = self.format.shard_count();
        for shard in 0..count {
            let dir = ready.join(steadq_names::shard_hex(shard));
            if fs::inotify::add_appear_watch(fd.as_fd(), &dir).is_err() {
                return;
            }
        }
        self.ready_watch = Some(fd);
    }

    fn lease_once_with_dirty(
        &mut self,
        lease_duration_ns: u64,
        mut _dirty: Option<&mut engine::DirtySet>,
    ) -> LeaseOutcome {
        if let Err(e) = self.check_not_poisoned() {
            return LeaseOutcome::NotCommitted(e);
        }

        // Validate lease duration: 1s to 7d
        if !lease_duration_is_valid(lease_duration_ns) {
            return LeaseOutcome::NotCommitted(Error::InvalidInput(
                "lease duration must be 1s to 7d".into(),
            ));
        }

        // Track scan completeness to distinguish Empty from I/O error
        let mut scan_had_error = false;
        let mut wall_floor = None;

        // Use and advance the per-worker scan round
        let scan_round = self.scan_round;
        self.scan_round = self.scan_round.wrapping_add(1);
        let (scheduled_start, stride) = steadq_names::shard_scan_params(
            self.format.queue_id(),
            &self.boot_id_bytes,
            &self.worker_nonce,
            scan_round,
            self.format.shard_count(),
        );
        let start = self.ready_shard_hint.take().unwrap_or(scheduled_start);

        for i in 0..self.format.shard_count() {
            let shard = steadq_names::shard_at(start, stride, i, self.format.shard_count());
            let shard_str = shard_hex(shard);

            // Open the ready shard directory
            let ready_dir = self.layout().ready_shard_dir(shard);
            let shard_fd = match open_relative(self.root_fd.as_fd(), &ready_dir) {
                Ok(fd) => fd,
                Err(_) => {
                    scan_had_error = true;
                    continue;
                }
            };

            let mut entries = match fs::DirectoryStream::open(shard_fd.as_fd()) {
                Ok(entries) => entries,
                Err(_) => {
                    scan_had_error = true;
                    continue;
                }
            };

            loop {
                let entry = match entries.next_entry() {
                    Ok(Some(entry)) => entry,
                    Ok(None) => break,
                    Err(_) => {
                        scan_had_error = true;
                        break;
                    }
                };
                let Some(entry) = entry.as_ascii_str() else {
                    scan_had_error = true;
                    continue;
                };
                if !entry.ends_with(".sqj") {
                    continue;
                }

                // Parse and verify the ready filename
                let parsed = match steadq_names::parse_ready(entry) {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                if !parsed.authenticate_tag(self.format.queue_id(), &shard_str) {
                    continue;
                }

                // Verify shard matches job_id
                let computed_shard = compute_shard(
                    self.format.queue_id(),
                    &parsed.common.job_id,
                    self.format.shard_count(),
                );
                if computed_shard != shard {
                    continue;
                }

                // Check attempt limit
                if parsed.common.attempt >= parsed.common.maximum_attempts {
                    let operation_wall_floor = match wall_floor {
                        Some(floor) => floor,
                        None => match self.wall_floor_for_mutation() {
                            Ok(floor) => {
                                wall_floor = Some(floor);
                                floor
                            }
                            Err(error) => return LeaseOutcome::NotCommitted(error),
                        },
                    };
                    // Move to dead
                    match self.move_to_dead(
                        &ready_dir,
                        entry,
                        &parsed.common,
                        DeadReason::AttemptsExhausted,
                        operation_wall_floor,
                    ) {
                        Ok(()) => continue,
                        // Nothing linearized: report and leave the handle usable.
                        Err(DeadLetterFailure::Invalid(error)) => {
                            return LeaseOutcome::NotCommitted(error);
                        }
                        Err(DeadLetterFailure::Move(engine::MoveFailure::SourceMissing)) => {
                            continue
                        }
                        Err(DeadLetterFailure::Move(engine::MoveFailure::AlreadyExists)) => {
                            self.poison(PoisonReason::InternalInvariantViolation);
                            return LeaseOutcome::NotCommitted(Error::IdentityCollision);
                        }
                        Err(DeadLetterFailure::Move(engine::MoveFailure::NotCommitted {
                            phase,
                            source,
                        })) => {
                            return LeaseOutcome::NotCommitted(match Error::from(source) {
                                Error::IoFailure(message) => Error::IoFailure(format!(
                                    "dead-letter move failed at {phase:?}: {message}"
                                )),
                                classified => classified,
                            });
                        }
                        Err(DeadLetterFailure::Move(engine::MoveFailure::OutcomeUnknown {
                            phase,
                            source,
                        })) => {
                            self.poison(PoisonReason::PostLinearizationStateUnknown);
                            return LeaseOutcome::NotCommitted(Error::IoFailure(format!(
                                "dead-letter move indeterminate at {phase:?}: {source}"
                            )));
                        }
                    }
                }

                // Re-capture clocks immediately before the claim
                let boottime_claim = match fs::clock_boottime_ns() {
                    Ok(t) => t,
                    Err(e) => return LeaseOutcome::NotCommitted(Error::from(e)),
                };
                let wall_claim = match wall_floor {
                    Some(floor) => floor.unix_ns(),
                    None => match self.wall_floor_for_mutation() {
                        Ok(floor) => {
                            wall_floor = Some(floor);
                            floor.unix_ns()
                        }
                        Err(error) => return LeaseOutcome::NotCommitted(error),
                    },
                };
                // Attempt claim: rename ready -> leased
                let lease_token = match fs::random_128bit() {
                    Ok(t) => t,
                    Err(e) => return LeaseOutcome::NotCommitted(Error::from(e)),
                };
                let boottime_deadline = match boottime_claim.checked_add(lease_duration_ns) {
                    Some(d) => d,
                    None => continue, // deadline overflow, skip this candidate
                };
                let wall_deadline = match wall_claim.checked_add(lease_duration_ns) {
                    Some(d) => d,
                    None => continue,
                };

                let leased_common = match next_identity(ProtocolOperation::Claim, &parsed.common) {
                    Ok(common) => common,
                    Err(_) => continue,
                };
                let new_generation = leased_common.generation;
                let new_attempt = leased_common.attempt;

                let lease_target = match self.layout().leased_for_boot(
                    &leased_common,
                    &self.boot_id,
                    boottime_deadline,
                    wall_deadline,
                    &lease_token,
                ) {
                    Ok(target) => target,
                    Err(_) => {
                        scan_had_error = true;
                        continue;
                    }
                };
                let leased_dir = lease_target.directory();
                if let Err(e) = self.ensure_dir_with_dirty(&leased_dir, _dirty.as_deref_mut()) {
                    // Propagate real errors, don't mask as scan miss
                    scan_had_error = true;
                    let _ = e;
                    continue;
                }

                let leased_dir_fd = match open_relative(self.root_fd.as_fd(), &leased_dir) {
                    Ok(fd) => fd,
                    Err(error) => match classify_lease_directory_open_failure(&error) {
                        LeaseDirectoryOpenFailure::Gone => continue,
                        LeaseDirectoryOpenFailure::InvalidDirectory
                        | LeaseDirectoryOpenFailure::Io => {
                            scan_had_error = true;
                            continue;
                        }
                    },
                };

                let claim_source = match Self::open_claim_source(
                    shard_fd.as_fd(),
                    entry,
                    &parsed.common.job_id,
                    parsed.common.maximum_attempts,
                ) {
                    Ok(Some(source)) => source,
                    Ok(None) => continue,
                    Err(Error::IoFailure(_)) => {
                        scan_had_error = true;
                        continue;
                    }
                    Err(error) => return LeaseOutcome::NotCommitted(error),
                };
                let mut claim_ticket = match self.claim_transition_ticket(
                    &parsed.common,
                    lease_token,
                    claim_source.evidence.clone(),
                    boottime_deadline,
                    wall_deadline,
                ) {
                    Ok(ticket) => ticket,
                    Err(error) => return LeaseOutcome::NotCommitted(error),
                };

                match observe_witness_path(
                    shard_fd.as_fd(),
                    entry,
                    claim_source.device,
                    claim_source.inode,
                ) {
                    Ok(WitnessPathObservation::Match) => {}
                    Ok(WitnessPathObservation::Gone) => continue,
                    Ok(WitnessPathObservation::Mismatch) => {
                        return LeaseOutcome::NotCommitted(Error::QueueCorrupt(
                            "ready source identity changed before claim".into(),
                        ));
                    }
                    Err(_) => {
                        scan_had_error = true;
                        continue;
                    }
                }

                let move_result = if _dirty.is_some() {
                    let result = engine::move_witnessed_noreplace_deferred(
                        shard_fd.as_fd(),
                        entry,
                        leased_dir_fd.as_fd(),
                        &lease_target.filename,
                        engine::MoveIdentity::new(claim_source.device, claim_source.inode),
                        |_| {
                            let refreshed_evidence = Self::read_claim_ticket_evidence(
                                claim_source.file_fd.as_fd(),
                                &parsed.common.job_id,
                                parsed.common.maximum_attempts,
                            )
                            .map_err(|error| std::io::Error::other(error.to_string()))?;
                            claim_ticket = self
                                .claim_transition_ticket(
                                    &parsed.common,
                                    lease_token,
                                    refreshed_evidence,
                                    boottime_deadline,
                                    wall_deadline,
                                )
                                .map_err(|error| std::io::Error::other(error.to_string()))?;
                            Ok(())
                        },
                    );
                    if result.is_ok() {
                        if let Some(d) = _dirty.as_deref_mut() {
                            if d.record(shard_fd.as_fd())
                                .and_then(|()| d.record(leased_dir_fd.as_fd()))
                                .is_err()
                            {
                                self.poison(PoisonReason::PostLinearizationStateUnknown);
                                return LeaseOutcome::OutcomeUnknown(
                                    claim_ticket
                                        .with_phase(TransitionPhase::DestinationDirectoryDurable),
                                );
                            }
                        }
                    }
                    result
                } else {
                    engine::move_witnessed_noreplace_with(
                        shard_fd.as_fd(),
                        entry,
                        leased_dir_fd.as_fd(),
                        &lease_target.filename,
                        engine::MoveIdentity::new(claim_source.device, claim_source.inode),
                        |_| {
                            let refreshed_evidence = Self::read_claim_ticket_evidence(
                                claim_source.file_fd.as_fd(),
                                &parsed.common.job_id,
                                parsed.common.maximum_attempts,
                            )
                            .map_err(|error| std::io::Error::other(error.to_string()))?;
                            claim_ticket = self
                                .claim_transition_ticket(
                                    &parsed.common,
                                    lease_token,
                                    refreshed_evidence,
                                    boottime_deadline,
                                    wall_deadline,
                                )
                                .map_err(|error| std::io::Error::other(error.to_string()))?;
                            Ok(())
                        },
                    )
                };
                match move_result {
                    Ok((leased_object, ())) => {
                        // The claim is committed; a failure here is corruption or
                        // indeterminate, never Empty.
                        let leased_file = claim_source.file_fd;
                        let Some((header, content_type)) = self.validate_claimed_object(
                            leased_file.as_fd(),
                            leased_object.size(),
                            &parsed.common,
                        ) else {
                            self.poison(PoisonReason::PostLinearizationStateUnknown);
                            return LeaseOutcome::OutcomeUnknown(
                                claim_ticket.with_phase(TransitionPhase::SourceDirectoryDurable),
                            );
                        };
                        // Verify payload digest on held fd before delivery.
                        // Deterministic PayloadCorrupt is quarantined, not delivered.
                        // Indeterminate I/O poisons and yields OutcomeUnknown.
                        if let Err(e) = self.verify_payload_on_fd(leased_file.as_fd()) {
                            match e {
                                Error::PayloadCorrupt => {
                                    match self.quarantine_corrupt_lease(
                                        leased_dir_fd.as_fd(),
                                        &lease_target.filename,
                                        leased_file.as_fd(),
                                    ) {
                                        Ok(()) => {
                                            return LeaseOutcome::NotCommitted(
                                                Error::PayloadCorrupt,
                                            );
                                        }
                                        Err(failure) => {
                                            self.poison(
                                                PoisonReason::PostLinearizationStateUnknown,
                                            );
                                            return LeaseOutcome::OutcomeUnknown(
                                                claim_ticket.with_phase(failure.phase().map_or(
                                                    TransitionPhase::SourceDirectoryDurable,
                                                    ticket_phase_for_move_outcome_unknown,
                                                )),
                                            );
                                        }
                                    }
                                }
                                _ => {
                                    self.poison(PoisonReason::PostLinearizationStateUnknown);
                                    return LeaseOutcome::OutcomeUnknown(
                                        claim_ticket
                                            .with_phase(TransitionPhase::SourceDirectoryDurable),
                                    );
                                }
                            }
                        }
                        let lease_info = LeaseInfo {
                            job_id: parsed.common.job_id,
                            envelope_digest: header.envelope_digest,
                            generation: new_generation,
                            attempt: new_attempt,
                            maximum_attempts: parsed.common.maximum_attempts,
                            token: lease_token,
                            boot_id: self.boot_id.clone(),
                            expires_boottime_ns: boottime_deadline,
                            expires_wall_ns: wall_deadline,
                            content_type,
                            payload_length: header.payload_length,
                            payload_digest: header.payload_digest,
                            expected_dev: leased_object.device(),
                            expected_inode: leased_object.inode(),
                            exact_source_path: format!("{leased_dir}/{}", lease_target.filename),
                        };

                        return LeaseOutcome::Leased(lease_info);
                    }
                    Err(engine::MoveFailure::SourceMissing) => continue,
                    Err(engine::MoveFailure::OutcomeUnknown { phase, .. }) => {
                        self.poison(PoisonReason::PostLinearizationStateUnknown);
                        return LeaseOutcome::OutcomeUnknown(
                            claim_ticket.with_phase(ticket_phase_for_move_outcome_unknown(phase)),
                        );
                    }
                    Err(
                        engine::MoveFailure::AlreadyExists
                        | engine::MoveFailure::NotCommitted { .. },
                    ) => {
                        scan_had_error = true;
                        continue;
                    }
                }
            }
        }

        // If the scan had I/O errors, report them rather than returning Empty
        if scan_had_error {
            LeaseOutcome::NotCommitted(Error::IoFailure("scan completed with errors".into()))
        } else {
            LeaseOutcome::Empty
        }
    }
}

/// Why the claim-time dead-letter move did not complete.
#[derive(Debug)]
pub(super) enum DeadLetterFailure {
    /// The identity or bucket arithmetic rejected the object; nothing was
    /// touched on disk. Carries the already-classified error.
    Invalid(Error),
    Move(engine::MoveFailure),
}

impl Queue {
    /// Structural checks on a just-claimed object: header, filename
    /// agreement, envelope digest, exact size, payload limit, and extension
    /// decode. `None` means the committed claim cannot be delivered.
    pub(super) fn validate_claimed_object(
        &self,
        file: BorrowedFd<'_>,
        size: u64,
        common: &CommonFields,
    ) -> Option<(FixedHeader, String)> {
        let mut header_buf = [0u8; 128];
        fs::pread_exact(file, &mut header_buf, 0).ok()?;
        let header = FixedHeader::decode(&header_buf).ok()?;
        if header.job_id != common.job_id || header.maximum_attempts != common.maximum_attempts {
            return None;
        }
        let ext_len = header.extension_header_length as usize;
        if verified::is_extension_too_large(ext_len) {
            return None;
        }
        let mut ext_buf = vec![0u8; ext_len];
        fs::pread_exact(file, &mut ext_buf, 128).ok()?;
        if !steadq_format::verify_envelope_digest(&header, &ext_buf) {
            return None;
        }
        if verified::checked_total_size(ext_len, header.payload_length).ok()? != size {
            return None;
        }
        if !payload_length_is_valid(header.payload_length, self.format.max_payload_length()) {
            return None;
        }
        let content_type = if verified::is_extension_present(ext_len) {
            steadq_format::cbor::ExtensionHeader::decode(&ext_buf)
                .ok()?
                .content_type
        } else {
            String::new()
        };
        Some((header, content_type))
    }

    pub(super) fn claim_transition_ticket(
        &self,
        source: &CommonFields,
        lease_token: [u8; 16],
        evidence: TicketEvidence,
        boottime_deadline_ns: u64,
        wall_deadline_ns: u64,
    ) -> Result<TransitionTicket, Error> {
        TransitionTicket::new(
            *self.format.queue_id(),
            TransitionOperation::Claim,
            TransitionPhase::Linearized,
            TicketIdentity::new(
                source.job_id,
                source.generation,
                source.attempt,
                source.maximum_attempts,
                lease_token,
                evidence,
            ),
            TicketSource::Ready {},
            TicketDestination::Leased {
                boot_id: self.boot_id.clone(),
                boottime_deadline_ns,
                wall_deadline_ns,
            },
        )
    }

    pub(super) fn open_claim_source(
        directory_fd: BorrowedFd<'_>,
        name: &str,
        expected_job_id: &[u8; 16],
        expected_maximum_attempts: u32,
    ) -> Result<Option<ClaimSourceWitness>, Error> {
        let file = match fs::openat(directory_fd, name, resolver_file_open_flags(), 0) {
            Ok(file) => file,
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(None),
            Err(error) => return Err(Error::from(error)),
        };
        let stat = fs::fstat(file.as_fd()).map_err(Error::from)?;
        if !is_singly_linked_regular(stat.st_mode, stat.st_nlink) {
            return Err(Error::QueueCorrupt(
                "ready source is not a singly-linked regular file".into(),
            ));
        }
        let evidence = Self::read_claim_ticket_evidence(
            file.as_fd(),
            expected_job_id,
            expected_maximum_attempts,
        )?;
        Ok(Some(ClaimSourceWitness {
            file_fd: file,
            device: stat.st_dev as u64,
            inode: stat.st_ino as u64,
            evidence,
        }))
    }

    pub(super) fn read_claim_ticket_evidence(
        file_fd: BorrowedFd<'_>,
        expected_job_id: &[u8; 16],
        expected_maximum_attempts: u32,
    ) -> Result<TicketEvidence, Error> {
        let verified = verified::verify_envelope_on_fd(file_fd).map_err(Error::from)?;
        let header = verified.header();
        if &header.job_id != expected_job_id {
            return Err(Error::QueueCorrupt("header job_id mismatch".into()));
        }
        if header.maximum_attempts != expected_maximum_attempts {
            return Err(Error::QueueCorrupt(
                "header maximum_attempts mismatch".into(),
            ));
        }
        Ok(TicketEvidence::new(
            header.envelope_digest,
            header.payload_length,
        ))
    }

    /// Move a ready object to dead (for exhausted attempts cleanup).
    /// Move an attempt-exhausted ready object to dead. Failures before the
    /// rename are `NotCommitted` or `Invalid`; the caller reports them without
    /// poisoning, except `AlreadyExists`, an identity collision at the
    /// deterministic dead path. Failures after it are `OutcomeUnknown`.
    pub(super) fn move_to_dead(
        &mut self,
        ready_dir: &str,
        ready_name: &str,
        common: &CommonFields,
        reason: DeadReason,
        wall_floor: WallFloor,
    ) -> Result<(), DeadLetterFailure> {
        let terminal_bucket = steadq_math::bucket_number(
            wall_floor.unix_ns(),
            self.format.terminal_bucket_width_ns(),
        )
        .ok_or(DeadLetterFailure::Invalid(Error::StateExhausted))?;
        let dead_common = next_identity(ProtocolOperation::ExhaustedReadyCleanup, common)
            .map_err(DeadLetterFailure::Invalid)?;
        let target = self
            .layout()
            .dead_in_bucket(&dead_common, reason as u16, terminal_bucket);
        let dead_dir = target.directory();
        let not_committed = |phase| {
            move |source| {
                DeadLetterFailure::Move(engine::MoveFailure::NotCommitted { phase, source })
            }
        };
        self.ensure_dir(&dead_dir)
            .map_err(not_committed(engine::MovePhase::EnsureDest))?;
        let dead_dir_fd = open_relative(self.root_fd.as_fd(), &dead_dir)
            .map_err(not_committed(engine::MovePhase::EnsureDest))?;
        let ready_dir_fd = open_relative(self.root_fd.as_fd(), ready_dir)
            .map_err(not_committed(engine::MovePhase::PreRename))?;
        match engine::move_verified_noreplace(
            ready_dir_fd.as_fd(),
            ready_name,
            dead_dir_fd.as_fd(),
            &target.filename,
        ) {
            Ok(()) | Err(engine::MoveFailure::SourceMissing) => Ok(()),
            Err(failure) => Err(DeadLetterFailure::Move(failure)),
        }
    }
}
