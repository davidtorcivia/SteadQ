// Expired lease reaping to ready or dead.
use super::*;

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
            if let Some(cursor) = &self.recovery_cursor.reap_leases {
                if boot_dir_entry.as_bytes() < cursor.first.as_slice() {
                    continue;
                }
            }
            if Self::work_budget_exhausted(stats, budget, deadline_mono) {
                stats.budget_exhausted = true;
                return;
            }
            let Some(boot_dir_name) = boot_dir_entry.as_ascii_str() else {
                Self::record_error(
                    stats,
                    "reap_boot_name",
                    &raw_name_for_error(boot_dir_entry),
                    "boot directory name is not ASCII",
                );
                continue;
            };
            if steadq_names::boot_id_bytes(boot_dir_name).is_none() {
                Self::record_error(
                    stats,
                    "reap_boot_name",
                    boot_dir_name,
                    "boot directory name is not canonical",
                );
                continue;
            }

            let is_current_boot = boot_dir_name == self.boot_id;

            let boot_dir_fd = match fs::open_directory(leased_fd.as_fd(), boot_dir_name) {
                Ok(fd) => fd,
                Err(error) => {
                    stats.scan_skips += 1;
                    Self::block_phase(stats, "reap_boot_open", boot_dir_name, &error.to_string());
                    if !self.remember_hierarchy_retry_or_block(
                        RecoveryPhase::ReapLeases,
                        RecoveryHierarchyRetryKind::Open,
                        &[boot_dir_entry.as_bytes()],
                        stats,
                        boot_dir_name,
                    ) {
                        return;
                    }
                    continue;
                }
            };

            let mut bucket_dirs = match read_recovery_directory(
                boot_dir_fd.as_fd(),
                deadline_mono,
                scan.budget,
                scan.stats,
            ) {
                Ok(e) => e,
                Err(error) => {
                    stats.scan_skips += 1;
                    if Self::record_directory_error(
                        stats,
                        "reap_bucket_read",
                        boot_dir_name,
                        &error,
                    ) {
                        return;
                    }
                    if !self.remember_hierarchy_retry_or_block(
                        RecoveryPhase::ReapLeases,
                        RecoveryHierarchyRetryKind::Enumerate,
                        &[boot_dir_entry.as_bytes()],
                        stats,
                        boot_dir_name,
                    ) {
                        return;
                    }
                    continue;
                }
            };
            bucket_dirs.sort();

            for bucket_entry in &bucket_dirs {
                if let Some(cursor) = &self.recovery_cursor.reap_leases {
                    if boot_dir_entry.as_bytes() == cursor.first
                        && bucket_entry.as_bytes() < cursor.second.as_slice()
                    {
                        continue;
                    }
                }
                if Self::work_budget_exhausted(stats, budget, deadline_mono) {
                    stats.budget_exhausted = true;
                    return;
                }
                let Some(bucket_name) = bucket_entry.as_ascii_str() else {
                    Self::record_error(
                        stats,
                        "reap_bucket_name",
                        &raw_name_for_error(bucket_entry),
                        "bucket directory name is not ASCII",
                    );
                    continue;
                };
                let Some(bucket_num) = steadq_names::bucket_from_hex(bucket_name) else {
                    Self::record_error(
                        stats,
                        "reap_bucket_name",
                        bucket_name,
                        "bucket directory name is not canonical",
                    );
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

                let bucket_fd = match fs::open_directory(boot_dir_fd.as_fd(), bucket_name) {
                    Ok(fd) => fd,
                    Err(error) => {
                        stats.scan_skips += 1;
                        Self::block_phase(
                            stats,
                            "reap_bucket_open",
                            &format!("leased/{boot_dir_name}/{bucket_name}"),
                            &error.to_string(),
                        );
                        if !self.remember_hierarchy_retry_or_block(
                            RecoveryPhase::ReapLeases,
                            RecoveryHierarchyRetryKind::Open,
                            &[boot_dir_entry.as_bytes(), bucket_entry.as_bytes()],
                            stats,
                            &format!("leased/{boot_dir_name}/{bucket_name}"),
                        ) {
                            return;
                        }
                        continue;
                    }
                };

                let mut shard_dirs = match read_recovery_directory(
                    bucket_fd.as_fd(),
                    deadline_mono,
                    scan.budget,
                    scan.stats,
                ) {
                    Ok(e) => e,
                    Err(error) => {
                        stats.scan_skips += 1;
                        if Self::record_directory_error(
                            stats,
                            "reap_shard_read",
                            &format!("leased/{boot_dir_name}/{bucket_name}"),
                            &error,
                        ) {
                            return;
                        }
                        if !self.remember_hierarchy_retry_or_block(
                            RecoveryPhase::ReapLeases,
                            RecoveryHierarchyRetryKind::Enumerate,
                            &[boot_dir_entry.as_bytes(), bucket_entry.as_bytes()],
                            stats,
                            &format!("leased/{boot_dir_name}/{bucket_name}"),
                        ) {
                            return;
                        }
                        continue;
                    }
                };
                shard_dirs.sort();

                for shard_entry in &shard_dirs {
                    if let Some(cursor) = &self.recovery_cursor.reap_leases {
                        if boot_dir_entry.as_bytes() == cursor.first
                            && bucket_entry.as_bytes() == cursor.second
                            && shard_entry.as_bytes() < cursor.third.as_slice()
                        {
                            continue;
                        }
                    }
                    let Some(shard_name) = shard_entry.as_ascii_str() else {
                        Self::record_error(
                            stats,
                            "reap_shard_name",
                            &raw_name_for_error(shard_entry),
                            "shard directory name is not ASCII",
                        );
                        continue;
                    };
                    let Some(shard) = steadq_names::shard_from_hex(shard_name) else {
                        Self::record_error(
                            stats,
                            "reap_shard_name",
                            shard_name,
                            "shard directory name is not canonical",
                        );
                        continue;
                    };
                    if shard >= self.format.shard_count() {
                        Self::record_error(
                            stats,
                            "reap_shard_name",
                            shard_name,
                            "shard directory is outside the queue shard range",
                        );
                        continue;
                    }
                    let shard_fd = match fs::open_directory(bucket_fd.as_fd(), shard_name) {
                        Ok(fd) => fd,
                        Err(error) => {
                            stats.scan_skips += 1;
                            Self::block_phase(
                                stats,
                                "reap_shard_open",
                                &format!("leased/{boot_dir_name}/{bucket_name}/{shard_name}"),
                                &error.to_string(),
                            );
                            if !self.remember_hierarchy_retry_or_block(
                                RecoveryPhase::ReapLeases,
                                RecoveryHierarchyRetryKind::Open,
                                &[
                                    boot_dir_entry.as_bytes(),
                                    bucket_entry.as_bytes(),
                                    shard_entry.as_bytes(),
                                ],
                                stats,
                                &format!("leased/{boot_dir_name}/{bucket_name}/{shard_name}"),
                            ) {
                                return;
                            }
                            continue;
                        }
                    };

                    let mut entries = match read_recovery_directory(
                        shard_fd.as_fd(),
                        deadline_mono,
                        scan.budget,
                        scan.stats,
                    ) {
                        Ok(e) => e,
                        Err(error) => {
                            stats.scan_skips += 1;
                            if Self::record_directory_error(
                                stats,
                                "reap_entry_read",
                                &format!("leased/{boot_dir_name}/{bucket_name}/{shard_name}"),
                                &error,
                            ) {
                                return;
                            }
                            if !self.remember_hierarchy_retry_or_block(
                                RecoveryPhase::ReapLeases,
                                RecoveryHierarchyRetryKind::Enumerate,
                                &[
                                    boot_dir_entry.as_bytes(),
                                    bucket_entry.as_bytes(),
                                    shard_entry.as_bytes(),
                                ],
                                stats,
                                &format!("leased/{boot_dir_name}/{bucket_name}/{shard_name}"),
                            ) {
                                return;
                            }
                            continue;
                        }
                    };
                    entries.sort();

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

                        // Parse the leased filename to get deadline and attempt info
                        let parsed = match steadq_names::parse_leased(entry) {
                            Ok(p) => p,
                            Err(_) => {
                                let relative_path = format!(
                                    "leased/{boot_dir_name}/{bucket_name}/{shard_name}/{entry}"
                                );
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
                                &format!(
                                    "leased/{boot_dir_name}/{bucket_name}/{shard_name}/{entry}"
                                ),
                                &format!("{e}"),
                            );
                            // Quarantine corrupt objects
                            if matches!(e, Error::QueueCorrupt(_))
                                && !self.quarantine_recovery_object(
                                    RecoveryQuarantineCandidate {
                                        source_directory_fd: shard_fd.as_fd(),
                                        filename: entry,
                                        relative_path: &format!(
                                            "leased/{boot_dir_name}/{bucket_name}/{shard_name}/{entry}"
                                        ),
                                        reason: crate::QuarantineReason::EnvelopeCorrupt,
                                    },
                                    stats,
                                    budget)
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
                                &format!(
                                    "leased/{boot_dir_name}/{bucket_name}/{shard_name}/{entry}"
                                ),
                                "invalid lease bucket width",
                            );
                            return;
                        };
                        let actual_bucket = match u64::from_str_radix(bucket_name, 16) {
                            Ok(bucket) => bucket,
                            Err(_) => {
                                Self::record_error(
                                    stats,
                                    "reap_bucket_check",
                                    &format!(
                                        "leased/{boot_dir_name}/{bucket_name}/{shard_name}/{entry}"
                                    ),
                                    "invalid lease bucket name",
                                );
                                continue;
                            }
                        };
                        if actual_bucket != expected_lease_bucket {
                            Self::record_error(
                                stats,
                                "reap_bucket_check",
                                &format!(
                                    "leased/{boot_dir_name}/{bucket_name}/{shard_name}/{entry}"
                                ),
                                &format!(
                                    "bucket mismatch: dir {actual_bucket} != deadline-derived {expected_lease_bucket}"
                                ));
                            continue;
                        }

                        // Determine destination: ready or dead
                        if parsed.common.attempt >= parsed.common.maximum_attempts {
                            let Some(wall_floor) = wall_floor else {
                                Self::record_error(
                                    stats,
                                    "reap_to_dead",
                                    &format!(
                                        "leased/{boot_dir_name}/{bucket_name}/{shard_name}/{entry}"
                                    ),
                                    "authenticated wall floor unavailable",
                                );
                                continue;
                            };
                            // Move to dead
                            let relative_path = format!(
                                "leased/{boot_dir_name}/{bucket_name}/{shard_name}/{entry}"
                            );
                            stats.operations_attempted += 1;
                            match self.reap_to_dead(
                                shard_fd.as_fd(),
                                entry,
                                &parsed.common,
                                DeadReason::AttemptsExhausted,
                                wall_floor,
                            ) {
                                Ok(()) => stats.leases_to_dead += 1,
                                Err(failure) => Self::record_move_failure(
                                    stats,
                                    "reap_to_dead",
                                    &relative_path,
                                    failure,
                                ),
                            }
                        } else {
                            // Move to ready
                            let relative_path = format!(
                                "leased/{boot_dir_name}/{bucket_name}/{shard_name}/{entry}"
                            );
                            stats.operations_attempted += 1;
                            match self.reap_to_ready(
                                shard_fd.as_fd(),
                                shard_name,
                                entry,
                                &parsed.common,
                            ) {
                                Ok(()) => stats.leases_reaped += 1,
                                Err(failure) => Self::record_move_failure(
                                    stats,
                                    "reap_to_ready",
                                    &relative_path,
                                    failure,
                                ),
                            }
                        }
                    }
                }
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
        let first_shard = self.recovery_cursor.reap_colocated_shard.unwrap_or(0);
        for shard in first_shard..self.format.shard_count() {
            if Self::work_budget_exhausted(stats, budget, deadline_mono) {
                stats.budget_exhausted = true;
                self.recovery_cursor.reap_colocated_shard = Some(shard);
                return;
            }
            let ready_dir = self.layout().ready_shard_dir(shard);
            let shard_fd = match open_relative(self.root_fd(), &ready_dir) {
                Ok(fd) => fd,
                Err(error) => {
                    stats.scan_skips += 1;
                    Self::record_error(stats, "reap_shard_open", &ready_dir, &error.to_string());
                    continue;
                }
            };
            let mut entries = match read_recovery_directory(
                shard_fd.as_fd(),
                deadline_mono,
                scan.budget,
                scan.stats,
            ) {
                Ok(entries) => entries,
                Err(error) => {
                    stats.scan_skips += 1;
                    if Self::record_directory_error(stats, "reap_entry_read", &ready_dir, &error) {
                        return;
                    }
                    continue;
                }
            };
            entries.sort();
            let shard_name = steadq_names::shard_hex(shard);
            for raw_entry in entries {
                let Some(entry) = raw_entry.as_ascii_str() else {
                    continue;
                };
                let Ok(parsed) = steadq_names::parse_leased(entry) else {
                    continue;
                };
                let relative_path = format!("{ready_dir}/{entry}");
                let boot_id = steadq_names::format_boot_id(&parsed.boot_id);
                let Some(bucket) = steadq_math::lease_bucket(
                    parsed.boottime_deadline_ns,
                    self.format.lease_bucket_width_ns(),
                ) else {
                    Self::record_error(
                        stats,
                        "reap_bucket_check",
                        &relative_path,
                        "invalid lease bucket width",
                    );
                    continue;
                };
                let bucket_name = steadq_names::bucket_hex(bucket);
                if !parsed.authenticate_tag(
                    self.format.queue_id(),
                    &boot_id,
                    &bucket_name,
                    &shard_name,
                ) {
                    Self::record_error(stats, "reap_parse", &relative_path, "name tag mismatch");
                    continue;
                }
                let current_boot = boot_id == self.boot_id;
                if current_boot && parsed.boottime_deadline_ns > boottime_now {
                    continue;
                }
                let leased_ctx = crate::ActivePathContext::Leased {
                    boot_id: boot_id.clone(),
                    bucket: bucket_name.clone(),
                    shard: shard_name.clone(),
                };
                if let Err(error) =
                    self.validate_active_object(shard_fd.as_fd(), entry, &leased_ctx)
                {
                    Self::record_error(stats, "reap_validate", &relative_path, &format!("{error}"));
                    continue;
                }
                if Self::work_budget_exhausted(stats, budget, deadline_mono) {
                    stats.budget_exhausted = true;
                    self.recovery_cursor.reap_colocated_shard = Some(shard);
                    return;
                }
                stats.operations_attempted += 1;
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
                    match self.reap_colocated_to_dead(
                        shard_fd.as_fd(),
                        entry,
                        &parsed.common,
                        DeadReason::AttemptsExhausted,
                        wall_floor,
                    ) {
                        Ok(()) => stats.leases_to_dead += 1,
                        Err(failure) => Self::record_move_failure(
                            stats,
                            "reap_to_dead",
                            &relative_path,
                            failure,
                        ),
                    }
                } else {
                    match self.reap_colocated_to_ready(shard_fd.as_fd(), entry, &parsed.common) {
                        Ok(()) => stats.leases_reaped += 1,
                        Err(failure) => Self::record_move_failure(
                            stats,
                            "reap_to_ready",
                            &relative_path,
                            failure,
                        ),
                    }
                }
            }
        }
        self.recovery_cursor.reap_colocated_shard = None;
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

    pub(crate) fn reap_colocated_to_dead(
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
        move_verified_noreplace(src_fd, leased_name, dest_fd.as_fd(), &dead_target.filename)
    }

    pub(crate) fn reap_to_ready(
        &self,
        src_fd: BorrowedFd<'_>,
        shard: &str,
        leased_name: &str,
        common: &steadq_names::CommonFields,
    ) -> Result<(), MoveFailure> {
        let shard_num = match u32::from_str_radix(shard, 16) {
            Ok(n) => n,
            Err(_) => {
                return Err(MoveFailure::NotCommitted {
                    phase: MovePhase::PreRename,
                    source: std::io::Error::other(format!("invalid shard: {shard}")),
                })
            }
        };
        let dest_dir = self.layout().ready_shard_dir(shard_num);

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

    #[allow(clippy::too_many_arguments)]
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
