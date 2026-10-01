// Expired lease reaping to ready or dead.
use super::*;

/// A lease found in a ready shard by the colocated scan.
#[derive(Clone, Copy)]
struct ColocatedLease<'a> {
    shard_fd: BorrowedFd<'a>,
    shard_name: &'a str,
    entry: &'a str,
    relative_path: &'a str,
    parsed: &'a steadq_names::LeasedName,
}

impl Queue {
    pub(crate) fn reap_expired_leases(
        &mut self,
        boottime_now: u64,
        wall_floor: Option<WallFloor>,
        budget: &WorkBudget,
        scan: &mut RecoveryScanContext<'_>,
        stats: &mut RecoveryStats,
        deadline_mono: u64,
    ) {
        let root_fd = self.root_fd();

        // Scan leased/ directories
        let leased_fd = match fs::open_directory(root_fd, "leased") {
            Ok(fd) => fd,
            Err(e) => {
                Self::block_phase(stats, "open_leased_dir", "leased", &e.to_string());
                return;
            }
        };
        let hierarchy_retry = self.prepare_hierarchy_retry_phase(RecoveryPhase::ReapLeases);
        if self.retry_one_hierarchy_directory(
            RecoveryPhase::ReapLeases,
            hierarchy_retry,
            leased_fd.as_fd(),
            scan,
            stats,
            deadline_mono,
        ) {
            return;
        }
        // A saved colocated shard means leased/ finished earlier in this
        // cycle; rescanning it would spend the budget the shard needs.
        if self.recovery_cursor.reap_colocated_shard.is_some() {
            self.reap_colocated_ready_leases(
                boottime_now,
                wall_floor,
                budget,
                scan,
                stats,
                deadline_mono,
            );
            return;
        }

        let mut boot_dirs = match read_recovery_directory(
            leased_fd.as_fd(),
            deadline_mono,
            scan.budget,
            scan.stats,
        ) {
            Ok(e) => e,
            Err(e) => {
                Self::record_directory_error(stats, "read_leased_dirs", "leased", &e);
                return;
            }
        };
        boot_dirs.sort();

        for boot_dir_entry in &boot_dirs {
            if directory_before_cursor(
                self.recovery_cursor
                    .reap_leases
                    .as_ref()
                    .map(FourLevelCursor::directories),
                &[],
                boot_dir_entry.as_bytes(),
            ) {
                continue;
            }
            if Self::work_budget_exhausted(stats, budget, deadline_mono) {
                stats.budget_exhausted = true;
                return;
            }
            let Some(boot_dir_name) = boot_directory_name(stats, "reap_boot_name", boot_dir_entry)
            else {
                continue;
            };

            let is_current_boot = boot_dir_name == self.boot_id;

            let boot_path = format!("leased/{boot_dir_name}");
            let (boot_dir_fd, bucket_dirs) = match self.descend_level(
                leased_fd.as_fd(),
                &Level {
                    phase: RecoveryPhase::ReapLeases,
                    name: boot_dir_name,
                    components: &[boot_dir_entry.as_bytes()],
                    open_operation: "reap_boot_open",
                    read_operation: "reap_bucket_read",
                    path: &boot_path,
                },
                scan,
                stats,
                deadline_mono,
            ) {
                Descend::Entries(fd, entries) => (fd, entries),
                Descend::Skip => continue,
                Descend::Stop => return,
            };
            let mut absent_buckets = 0usize;

            for bucket_entry in &bucket_dirs {
                if directory_before_cursor(
                    self.recovery_cursor
                        .reap_leases
                        .as_ref()
                        .map(FourLevelCursor::directories),
                    &[boot_dir_entry.as_bytes()],
                    bucket_entry.as_bytes(),
                ) {
                    continue;
                }
                if Self::work_budget_exhausted(stats, budget, deadline_mono) {
                    stats.budget_exhausted = true;
                    return;
                }
                let Some((bucket_name, bucket_num)) =
                    bucket_directory_name(stats, "reap_bucket_name", bucket_entry)
                else {
                    continue;
                };

                // For current boot, check if bucket is expired
                if is_current_boot {
                    let Some(current_bucket) = steadq_math::bucket_number(
                        boottime_now,
                        self.format.lease_bucket_width_ns(),
                    ) else {
                        Self::block_phase(
                            stats,
                            "reap_bucket_check",
                            &format!("leased/{boot_dir_name}/{bucket_name}"),
                            "invalid lease bucket width",
                        );
                        return;
                    };
                    if bucket_num > current_bucket {
                        continue; // Not yet eligible
                    }
                }

                let bucket_path = format!("leased/{boot_dir_name}/{bucket_name}");
                let (bucket_fd, shard_dirs) = match self.descend_level(
                    boot_dir_fd.as_fd(),
                    &Level {
                        phase: RecoveryPhase::ReapLeases,
                        name: bucket_name,
                        components: &[boot_dir_entry.as_bytes(), bucket_entry.as_bytes()],
                        open_operation: "reap_bucket_open",
                        read_operation: "reap_shard_read",
                        path: &bucket_path,
                    },
                    scan,
                    stats,
                    deadline_mono,
                ) {
                    Descend::Entries(fd, entries) => (fd, entries),
                    Descend::Skip => continue,
                    Descend::Stop => return,
                };
                let mut absent_shards = 0usize;

                for shard_entry in &shard_dirs {
                    if directory_before_cursor(
                        self.recovery_cursor
                            .reap_leases
                            .as_ref()
                            .map(FourLevelCursor::directories),
                        &[boot_dir_entry.as_bytes(), bucket_entry.as_bytes()],
                        shard_entry.as_bytes(),
                    ) {
                        continue;
                    }
                    let Some((shard_name, shard)) = shard_directory_name(
                        stats,
                        "reap_shard_name",
                        shard_entry,
                        self.format.shard_count(),
                    ) else {
                        continue;
                    };
                    let shard_path = format!("leased/{boot_dir_name}/{bucket_name}/{shard_name}");
                    let (shard_fd, entries) = match self.descend_level(
                        bucket_fd.as_fd(),
                        &Level {
                            phase: RecoveryPhase::ReapLeases,
                            name: shard_name,
                            components: &[
                                boot_dir_entry.as_bytes(),
                                bucket_entry.as_bytes(),
                                shard_entry.as_bytes(),
                            ],
                            open_operation: "reap_shard_open",
                            read_operation: "reap_entry_read",
                            path: &shard_path,
                        },
                        scan,
                        stats,
                        deadline_mono,
                    ) {
                        Descend::Entries(fd, entries) => (fd, entries),
                        Descend::Skip => continue,
                        Descend::Stop => return,
                    };
                    let mut absent_entries = 0usize;

                    for raw_entry in &entries {
                        if let Some(cursor) = &self.recovery_cursor.reap_leases {
                            if cursor.should_skip(
                                boot_dir_entry.as_bytes(),
                                bucket_entry.as_bytes(),
                                shard_entry.as_bytes(),
                                raw_entry.as_bytes(),
                            ) {
                                continue;
                            }
                        }
                        if Self::work_budget_exhausted(stats, budget, deadline_mono) {
                            stats.budget_exhausted = true;
                            return;
                        }
                        let previous_entry_cursor = self.recovery_cursor.reap_leases.clone();
                        self.recovery_cursor.reap_leases = Some(FourLevelCursor::new(
                            boot_dir_entry.as_bytes(),
                            bucket_entry.as_bytes(),
                            shard_entry.as_bytes(),
                            raw_entry.as_bytes(),
                        ));
                        let Some(entry) = raw_entry.as_ascii_str() else {
                            Self::record_error(
                                stats,
                                "reap_entry_name",
                                &raw_name_for_error(raw_entry),
                                "entry name is not ASCII",
                            );
                            continue;
                        };

                        if !entry.ends_with(".sqj") {
                            continue;
                        }
                        let relative_path =
                            format!("leased/{boot_dir_name}/{bucket_name}/{shard_name}/{entry}");

                        // Parse the leased filename to get deadline and attempt info
                        let parsed = match steadq_names::parse_leased(entry) {
                            Ok(p) => p,
                            Err(_) => {
                                Self::record_error(
                                    stats,
                                    "reap_parse",
                                    &relative_path,
                                    "malformed leased filename",
                                );
                                if !self.quarantine_recovery_object(
                                    RecoveryQuarantineCandidate {
                                        source_directory_fd: shard_fd.as_fd(),
                                        filename: entry,
                                        relative_path: &relative_path,
                                        reason: crate::QuarantineReason::FilenameParseFailed,
                                    },
                                    stats,
                                    budget,
                                ) {
                                    self.recovery_cursor.reap_leases = previous_entry_cursor;
                                    return;
                                }
                                continue;
                            }
                        };

                        // For current boot, check actual deadline
                        if is_current_boot && parsed.boottime_deadline_ns > boottime_now {
                            continue;
                        }

                        // Validate object structure before recovery transition
                        let leased_ctx = crate::ActivePathContext::Leased {
                            boot_id: boot_dir_name.to_string(),
                            bucket: bucket_name.to_string(),
                            shard: shard_name.to_string(),
                        };
                        if let Err(e) =
                            self.validate_active_object(shard_fd.as_fd(), entry, &leased_ctx)
                        {
                            Self::record_error(
                                stats,
                                "reap_validate",
                                &relative_path,
                                &format!("{e}"),
                            );
                            // Quarantine corrupt objects
                            if matches!(e, Error::QueueCorrupt(_))
                                && !self.quarantine_recovery_object(
                                    RecoveryQuarantineCandidate {
                                        source_directory_fd: shard_fd.as_fd(),
                                        filename: entry,
                                        relative_path: &relative_path,
                                        reason: crate::QuarantineReason::EnvelopeCorrupt,
                                    },
                                    stats,
                                    budget,
                                )
                            {
                                self.recovery_cursor.reap_leases = previous_entry_cursor;
                                return;
                            }
                            continue;
                        }

                        // Verify bucket placement matches deadline-derived bucket
                        let Some(expected_lease_bucket) = steadq_math::lease_bucket(
                            parsed.boottime_deadline_ns,
                            self.format.lease_bucket_width_ns(),
                        ) else {
                            Self::record_error(
                                stats,
                                "reap_bucket_check",
                                &relative_path,
                                "invalid lease bucket width",
                            );
                            return;
                        };
                        if bucket_num != expected_lease_bucket {
                            Self::record_error(
                                stats,
                                "reap_bucket_check",
                                &relative_path,
                                &format!(
                                    "bucket mismatch: dir {bucket_num} != deadline-derived {expected_lease_bucket}"
                                ),
                            );
                            continue;
                        }

                        // Determine destination: ready or dead
                        if parsed.common.attempt >= parsed.common.maximum_attempts {
                            let Some(wall_floor) = wall_floor else {
                                Self::record_error(
                                    stats,
                                    "reap_to_dead",
                                    &relative_path,
                                    "authenticated wall floor unavailable",
                                );
                                continue;
                            };
                            stats.operations_attempted += 1;
                            match self.reap_to_dead(
                                shard_fd.as_fd(),
                                entry,
                                &parsed.common,
                                DeadReason::AttemptsExhausted,
                                wall_floor,
                            ) {
                                Ok(()) => {
                                    stats.leases_to_dead += 1;
                                    absent_entries += 1;
                                }
                                Err(failure) => {
                                    if matches!(failure, MoveFailure::SourceMissing) {
                                        absent_entries += 1;
                                    }
                                    Self::record_move_failure(
                                        stats,
                                        "reap_to_dead",
                                        &relative_path,
                                        failure,
                                    )
                                }
                            }
                        } else {
                            stats.operations_attempted += 1;
                            match self.reap_to_ready(shard_fd.as_fd(), shard, entry, &parsed.common)
                            {
                                Ok(()) => {
                                    stats.leases_reaped += 1;
                                    absent_entries += 1;
                                }
                                Err(failure) => {
                                    if matches!(failure, MoveFailure::SourceMissing) {
                                        absent_entries += 1;
                                    }
                                    Self::record_move_failure(
                                        stats,
                                        "reap_to_ready",
                                        &relative_path,
                                        failure,
                                    )
                                }
                            }
                        }
                    }

                    // New leases stay in ready/, so only a process from an
                    // older release running on that boot writes here.
                    if is_current_boot
                        || !all_observed_children_absent(absent_entries, entries.len())
                    {
                        continue;
                    }
                    match Self::prune_empty_directory(
                        bucket_fd.as_fd(),
                        shard_name,
                        "reap_shard_remove",
                        &shard_path,
                        budget,
                        stats,
                        deadline_mono,
                    ) {
                        Prune::Removed => {
                            stats.shards_removed += 1;
                            absent_shards += 1;
                        }
                        Prune::Missing => absent_shards += 1,
                        Prune::Kept => {}
                        Prune::Stop => return,
                    }
                }

                if is_current_boot || !all_observed_children_absent(absent_shards, shard_dirs.len())
                {
                    continue;
                }
                match Self::prune_empty_directory(
                    boot_dir_fd.as_fd(),
                    bucket_name,
                    "reap_bucket_remove",
                    &bucket_path,
                    budget,
                    stats,
                    deadline_mono,
                ) {
                    Prune::Removed => {
                        stats.buckets_removed += 1;
                        absent_buckets += 1;
                    }
                    Prune::Missing => absent_buckets += 1,
                    Prune::Kept => {}
                    Prune::Stop => return,
                }
            }

            if is_current_boot || !all_observed_children_absent(absent_buckets, bucket_dirs.len()) {
                continue;
            }
            match Self::prune_empty_directory(
                leased_fd.as_fd(),
                boot_dir_name,
                "reap_boot_remove",
                &boot_path,
                budget,
                stats,
                deadline_mono,
            ) {
                Prune::Removed | Prune::Missing | Prune::Kept => {}
                Prune::Stop => return,
            }
        }
        self.recovery_cursor.reap_leases = None;
        self.reap_colocated_ready_leases(
            boottime_now,
            wall_floor,
            budget,
            scan,
            stats,
            deadline_mono,
        );
    }

    fn reap_colocated_ready_leases(
        &mut self,
        boottime_now: u64,
        wall_floor: Option<WallFloor>,
        budget: &WorkBudget,
        scan: &mut RecoveryScanContext<'_>,
        stats: &mut RecoveryStats,
        deadline_mono: u64,
    ) {
        // A ready shard holds the whole ready backlog, so its scan resumes at
        // a saved directory position instead of rereading the shard every
        // pass: a pass that runs out of budget saves the position before the
        // lease it stopped at, or after the last entry it read, and the next
        // pass starts there. Reaping renames by exact name with NOREPLACE and
        // a missing source is benign, so a stale or invalid position can only
        // reread entries or skip some until the scan starts over from 0 next
        // cycle; it never moves the wrong object.
        let first_shard = self.recovery_cursor.reap_colocated_shard.unwrap_or(0);
        for shard in first_shard..self.format.shard_count() {
            // Every early return below resumes at this shard.
            self.recovery_cursor.reap_colocated_shard = Some(shard);
            if Self::work_budget_exhausted(stats, budget, deadline_mono) {
                stats.budget_exhausted = true;
                return;
            }
            let mut position = self
                .recovery_cursor
                .reap_colocated_position
                .take()
                .unwrap_or(0);
            let ready_dir = self.layout().ready_shard_dir(shard);
            let shard_fd = match open_relative(self.root_fd(), &ready_dir) {
                Ok(fd) => fd,
                Err(error) => {
                    stats.scan_skips += 1;
                    Self::record_error(stats, "reap_shard_open", &ready_dir, &error.to_string());
                    continue;
                }
            };
            let shard_name = steadq_names::shard_hex(shard);
            let result = stream_recovery_directory(
                shard_fd.as_fd(),
                &mut position,
                deadline_mono,
                scan.budget,
                scan.stats,
                |raw_entry| {
                    let Some(entry) = raw_entry.as_ascii_str() else {
                        return ControlFlow::Continue(());
                    };
                    let Ok(parsed) = steadq_names::parse_leased(entry) else {
                        return ControlFlow::Continue(());
                    };
                    self.reap_colocated_lease(
                        &ColocatedLease {
                            shard_fd: shard_fd.as_fd(),
                            shard_name: &shard_name,
                            entry,
                            relative_path: &format!("{ready_dir}/{entry}"),
                            parsed: &parsed,
                        },
                        boottime_now,
                        wall_floor,
                        budget,
                        stats,
                        deadline_mono,
                    )
                },
            );
            let stop = match result {
                Ok(flow) => flow.is_break(),
                Err(error) => {
                    stats.scan_skips += 1;
                    Self::record_directory_error(stats, "reap_entry_read", &ready_dir, &error)
                }
            };
            if stop {
                self.recovery_cursor.reap_colocated_position = (position != 0).then_some(position);
                return;
            }
        }
        self.recovery_cursor.reap_colocated_shard = None;
    }

    /// Reap one lease found in a ready shard. Breaks, leaving the lease for
    /// the next pass, when the work budget runs out.
    fn reap_colocated_lease(
        &self,
        lease: &ColocatedLease<'_>,
        boottime_now: u64,
        wall_floor: Option<WallFloor>,
        budget: &WorkBudget,
        stats: &mut RecoveryStats,
        deadline_mono: u64,
    ) -> ControlFlow<()> {
        let ColocatedLease {
            shard_fd,
            shard_name,
            entry,
            relative_path,
            parsed,
        } = *lease;
        let boot_id = steadq_names::format_boot_id(&parsed.boot_id);
        let Some(bucket) = steadq_math::lease_bucket(
            parsed.boottime_deadline_ns,
            self.format.lease_bucket_width_ns(),
        ) else {
            Self::record_error(
                stats,
                "reap_bucket_check",
                relative_path,
                "invalid lease bucket width",
            );
            return ControlFlow::Continue(());
        };
        let bucket_name = steadq_names::bucket_hex(bucket);
        if !parsed.authenticate_tag(self.format.queue_id(), &boot_id, &bucket_name, shard_name) {
            Self::record_error(stats, "reap_parse", relative_path, "name tag mismatch");
            return ControlFlow::Continue(());
        }
        let current_boot = boot_id == self.boot_id;
        if current_boot && parsed.boottime_deadline_ns > boottime_now {
            return ControlFlow::Continue(());
        }
        let leased_ctx = crate::ActivePathContext::Leased {
            boot_id,
            bucket: bucket_name,
            shard: shard_name.to_string(),
        };
        if let Err(error) = self.validate_active_object(shard_fd, entry, &leased_ctx) {
            Self::record_error(stats, "reap_validate", relative_path, &format!("{error}"));
            if matches!(error, Error::QueueCorrupt(_))
                && !self.quarantine_recovery_object(
                    RecoveryQuarantineCandidate {
                        source_directory_fd: shard_fd,
                        filename: entry,
                        relative_path,
                        reason: crate::QuarantineReason::EnvelopeCorrupt,
                    },
                    stats,
                    budget,
                )
            {
                return ControlFlow::Break(());
            }
            return ControlFlow::Continue(());
        }
        if Self::work_budget_exhausted(stats, budget, deadline_mono) {
            stats.budget_exhausted = true;
            return ControlFlow::Break(());
        }
        if parsed.common.attempt >= parsed.common.maximum_attempts {
            let Some(wall_floor) = wall_floor else {
                Self::record_error(
                    stats,
                    "reap_to_dead",
                    relative_path,
                    "authenticated wall floor unavailable",
                );
                return ControlFlow::Continue(());
            };
            stats.operations_attempted += 1;
            match self.reap_to_dead(
                shard_fd,
                entry,
                &parsed.common,
                DeadReason::AttemptsExhausted,
                wall_floor,
            ) {
                Ok(()) => stats.leases_to_dead += 1,
                Err(failure) => {
                    Self::record_move_failure(stats, "reap_to_dead", relative_path, failure)
                }
            }
        } else {
            stats.operations_attempted += 1;
            match self.reap_colocated_to_ready(shard_fd, entry, &parsed.common) {
                Ok(()) => stats.leases_reaped += 1,
                Err(failure) => {
                    Self::record_move_failure(stats, "reap_to_ready", relative_path, failure)
                }
            }
        }
        ControlFlow::Continue(())
    }

    pub(crate) fn reap_colocated_to_ready(
        &self,
        shard_fd: BorrowedFd<'_>,
        leased_name: &str,
        common: &steadq_names::CommonFields,
    ) -> Result<(), MoveFailure> {
        let ready_common =
            crate::next_common_fields(crate::state_machine::Operation::ReapExpiredToReady, common)
                .map_err(|_| MoveFailure::NotCommitted {
                    phase: MovePhase::PreRename,
                    source: std::io::Error::other("generation or attempt overflow"),
                })?;
        let ready_name = self.layout().ready(&ready_common).filename;
        move_verified_noreplace(shard_fd, leased_name, shard_fd, &ready_name)
    }

    pub(crate) fn reap_to_ready(
        &self,
        src_fd: BorrowedFd<'_>,
        shard: u32,
        leased_name: &str,
        common: &steadq_names::CommonFields,
    ) -> Result<(), MoveFailure> {
        let dest_dir = self.layout().ready_shard_dir(shard);

        let ready_common =
            crate::next_common_fields(crate::state_machine::Operation::ReapExpiredToReady, common)
                .map_err(|_| MoveFailure::NotCommitted {
                    phase: MovePhase::PreRename,
                    source: std::io::Error::other("generation or attempt overflow"),
                })?;

        let ready_target = self.layout().ready(&ready_common);
        let ready_name = ready_target.filename;

        let dest_fd = open_relative(self.root_fd(), &dest_dir).map_err(|error| {
            MoveFailure::NotCommitted {
                phase: MovePhase::EnsureDest,
                source: error,
            }
        })?;

        move_verified_noreplace(src_fd, leased_name, dest_fd.as_fd(), &ready_name)
    }

    pub(crate) fn reap_to_dead(
        &self,
        src_fd: BorrowedFd<'_>,
        leased_name: &str,
        common: &steadq_names::CommonFields,
        reason: DeadReason,
        wall_floor: WallFloor,
    ) -> Result<(), MoveFailure> {
        let terminal_bucket = steadq_math::bucket_number(
            wall_floor.unix_ns(),
            self.format.terminal_bucket_width_ns(),
        )
        .ok_or_else(|| MoveFailure::NotCommitted {
            phase: MovePhase::PreRename,
            source: std::io::Error::other("terminal bucket overflow"),
        })?;

        let dead_common =
            crate::next_common_fields(crate::state_machine::Operation::ReapExpiredToDead, common)
                .map_err(|_| MoveFailure::NotCommitted {
                phase: MovePhase::PreRename,
                source: std::io::Error::other("generation or attempt overflow"),
            })?;

        let dead_target =
            self.layout()
                .dead_in_bucket(&dead_common, reason as u16, terminal_bucket);
        let dest_dir = dead_target.directory();
        let dead_name = dead_target.filename;

        self.ensure_dir(&dest_dir)
            .map_err(|error| MoveFailure::NotCommitted {
                phase: MovePhase::EnsureDest,
                source: error,
            })?;
        let dest_fd = open_relative(self.root_fd(), &dest_dir).map_err(|error| {
            MoveFailure::NotCommitted {
                phase: MovePhase::EnsureDest,
                source: error,
            }
        })?;

        move_verified_noreplace(src_fd, leased_name, dest_fd.as_fd(), &dead_name)
    }
}
