// Temp cleanup, receipt compaction, and retention deletion.
use super::*;

impl Queue {
    pub(crate) fn cleanup_temp_files(
        &mut self,
        boottime_now: u64,
        budget: &WorkBudget,
        scan: &mut RecoveryScanContext<'_>,
        stats: &mut RecoveryStats,
        deadline_mono: u64,
    ) {
        let root_fd = self.root_fd();
        let tmp_fd = match fs::open_directory(root_fd, "tmp") {
            Ok(fd) => fd,
            Err(error) => {
                Self::block_phase(stats, "temp_root_open", "tmp", &error.to_string());
                return;
            }
        };
        let hierarchy_retry = self.prepare_hierarchy_retry_phase(RecoveryPhase::CleanupTemp);
        if self.retry_one_hierarchy_directory(
            RecoveryPhase::CleanupTemp,
            hierarchy_retry,
            tmp_fd.as_fd(),
            scan,
            stats,
            deadline_mono,
        ) {
            return;
        }

        let mut boot_dirs =
            match read_recovery_directory(tmp_fd.as_fd(), deadline_mono, scan.budget, scan.stats) {
                Ok(e) => e,
                Err(error) => {
                    Self::record_directory_error(stats, "temp_boot_read", "tmp", &error);
                    return;
                }
            };
        boot_dirs.sort();

        for boot_entry in &boot_dirs {
            if let Some(cursor) = &self.recovery_cursor.cleanup_temp {
                if boot_entry.as_bytes() < cursor.first.as_slice() {
                    continue;
                }
            }
            if Self::work_budget_exhausted(stats, budget, deadline_mono) {
                stats.budget_exhausted = true;
                return;
            }
            let Some(boot_dir_name) = boot_entry.as_ascii_str() else {
                Self::record_error(
                    stats,
                    "temp_boot_name",
                    &raw_name_for_error(boot_entry),
                    "boot directory name is not ASCII",
                );
                continue;
            };
            if steadq_names::boot_id_bytes(boot_dir_name).is_none() {
                Self::record_error(
                    stats,
                    "temp_boot_name",
                    boot_dir_name,
                    "boot directory name is not canonical",
                );
                continue;
            }

            let is_current_boot = boot_dir_name == self.boot_id;

            let boot_dir_fd = match fs::open_directory(tmp_fd.as_fd(), boot_dir_name) {
                Ok(fd) => fd,
                Err(error) => {
                    stats.scan_skips += 1;
                    Self::block_phase(stats, "temp_boot_open", boot_dir_name, &error.to_string());
                    if !self.remember_hierarchy_retry_or_block(
                        RecoveryPhase::CleanupTemp,
                        RecoveryHierarchyRetryKind::Open,
                        &[boot_entry.as_bytes()],
                        stats,
                        boot_dir_name,
                    ) {
                        return;
                    }
                    continue;
                }
            };

            let mut shard_dirs = match read_recovery_directory(
                boot_dir_fd.as_fd(),
                deadline_mono,
                scan.budget,
                scan.stats,
            ) {
                Ok(e) => e,
                Err(error) => {
                    stats.scan_skips += 1;
                    if Self::record_directory_error(stats, "temp_shard_read", boot_dir_name, &error)
                    {
                        return;
                    }
                    if !self.remember_hierarchy_retry_or_block(
                        RecoveryPhase::CleanupTemp,
                        RecoveryHierarchyRetryKind::Enumerate,
                        &[boot_entry.as_bytes()],
                        stats,
                        boot_dir_name,
                    ) {
                        return;
                    }
                    continue;
                }
            };
            shard_dirs.sort();

            for shard_entry in &shard_dirs {
                if let Some(cursor) = &self.recovery_cursor.cleanup_temp {
                    if boot_entry.as_bytes() == cursor.first
                        && shard_entry.as_bytes() < cursor.second.as_slice()
                    {
                        continue;
                    }
                }
                let Some(shard_name) = shard_entry.as_ascii_str() else {
                    Self::record_error(
                        stats,
                        "temp_shard_name",
                        &raw_name_for_error(shard_entry),
                        "shard directory name is not ASCII",
                    );
                    continue;
                };
                let Some(shard) = steadq_names::shard_from_hex(shard_name) else {
                    Self::record_error(
                        stats,
                        "temp_shard_name",
                        shard_name,
                        "shard directory name is not canonical",
                    );
                    continue;
                };
                if shard >= self.format.shard_count() {
                    Self::record_error(
                        stats,
                        "temp_shard_name",
                        shard_name,
                        "shard directory is outside the queue shard range",
                    );
                    continue;
                }
                let shard_fd = match fs::open_directory(boot_dir_fd.as_fd(), shard_name) {
                    Ok(fd) => fd,
                    Err(error) => {
                        stats.scan_skips += 1;
                        Self::block_phase(
                            stats,
                            "temp_shard_open",
                            &format!("tmp/{boot_dir_name}/{shard_name}"),
                            &error.to_string(),
                        );
                        if !self.remember_hierarchy_retry_or_block(
                            RecoveryPhase::CleanupTemp,
                            RecoveryHierarchyRetryKind::Open,
                            &[boot_entry.as_bytes(), shard_entry.as_bytes()],
                            stats,
                            &format!("tmp/{boot_dir_name}/{shard_name}"),
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
                            "temp_entry_read",
                            &format!("tmp/{boot_dir_name}/{shard_name}"),
                            &error,
                        ) {
                            return;
                        }
                        if !self.remember_hierarchy_retry_or_block(
                            RecoveryPhase::CleanupTemp,
                            RecoveryHierarchyRetryKind::Enumerate,
                            &[boot_entry.as_bytes(), shard_entry.as_bytes()],
                            stats,
                            &format!("tmp/{boot_dir_name}/{shard_name}"),
                        ) {
                            return;
                        }
                        continue;
                    }
                };
                entries.sort();

                for raw_entry in &entries {
                    if let Some(cursor) = &self.recovery_cursor.cleanup_temp {
                        if cursor.should_skip(
                            boot_entry.as_bytes(),
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
                    self.recovery_cursor.cleanup_temp = Some(ThreeLevelCursor::new(
                        boot_entry.as_bytes(),
                        shard_entry.as_bytes(),
                        raw_entry.as_bytes(),
                    ));
                    let Some(entry) = raw_entry.as_ascii_str() else {
                        Self::record_error(
                            stats,
                            "temp_entry_name",
                            &raw_name_for_error(raw_entry),
                            "entry name is not ASCII",
                        );
                        continue;
                    };

                    if !entry.ends_with(".tmp") {
                        continue;
                    }

                    let should_delete = if !is_current_boot {
                        true
                    } else if let Ok(parsed) = steadq_names::parse_temp(entry) {
                        boottime_now.saturating_sub(parsed.created_boottime_ns)
                            > self.options.temporary_file_ttl_ns
                    } else {
                        false
                    };

                    if should_delete {
                        let relative_path = format!("tmp/{boot_dir_name}/{shard_name}/{entry}");
                        stats.operations_attempted += 1;
                        match unlink_verified(shard_fd.as_fd(), entry) {
                            Ok(()) => stats.temp_files_deleted += 1,
                            Err(failure) => Self::record_unlink_failure(
                                stats,
                                "temp_delete",
                                &relative_path,
                                failure,
                            ),
                        }
                    }
                }
            }
        }
        self.recovery_cursor.cleanup_temp = None;
    }

    pub(crate) fn compact_receipts_with_scan_budget(
        &mut self,
        budget: &WorkBudget,
        scan: &mut RecoveryScanContext<'_>,
        stats: &mut RecoveryStats,
        deadline_mono: u64,
    ) {
        let root_fd = self.root_fd();
        let receipts_fd = match fs::open_directory(root_fd, "receipts") {
            Ok(fd) => fd,
            Err(error) => {
                Self::block_phase(stats, "compact_root_open", "receipts", &error.to_string());
                return;
            }
        };
        let hierarchy_retry = self.prepare_hierarchy_retry_phase(RecoveryPhase::CompactReceipts);
        if self.retry_one_hierarchy_directory(
            RecoveryPhase::CompactReceipts,
            hierarchy_retry,
            receipts_fd.as_fd(),
            scan,
            stats,
            deadline_mono,
        ) {
            return;
        }

        let mut bucket_dirs = match read_recovery_directory(
            receipts_fd.as_fd(),
            deadline_mono,
            scan.budget,
            scan.stats,
        ) {
            Ok(e) => e,
            Err(error) => {
                Self::record_directory_error(stats, "compact_bucket_read", "receipts", &error);
                return;
            }
        };
        bucket_dirs.sort();

        for bucket_entry in &bucket_dirs {
            // Skip buckets already processed in a prior pass.
            if let Some(cursor) = &self.recovery_cursor.compact_receipts {
                if bucket_entry.as_bytes() < cursor.first.as_slice() {
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
                    "compact_bucket_name",
                    &raw_name_for_error(bucket_entry),
                    "bucket directory name is not ASCII",
                );
                continue;
            };
            if steadq_names::bucket_from_hex(bucket_name).is_none() {
                Self::record_error(
                    stats,
                    "compact_bucket_name",
                    bucket_name,
                    "bucket directory name is not canonical",
                );
                continue;
            }

            let bucket_fd = match fs::open_directory(receipts_fd.as_fd(), bucket_name) {
                Ok(fd) => fd,
                Err(error) => {
                    stats.scan_skips += 1;
                    Self::block_phase(
                        stats,
                        "compact_bucket_open",
                        &format!("receipts/{bucket_name}"),
                        &error.to_string(),
                    );
                    if !self.remember_hierarchy_retry_or_block(
                        RecoveryPhase::CompactReceipts,
                        RecoveryHierarchyRetryKind::Open,
                        &[bucket_entry.as_bytes()],
                        stats,
                        &format!("receipts/{bucket_name}"),
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
                        "compact_shard_read",
                        &format!("receipts/{bucket_name}"),
                        &error,
                    ) {
                        return;
                    }
                    if !self.remember_hierarchy_retry_or_block(
                        RecoveryPhase::CompactReceipts,
                        RecoveryHierarchyRetryKind::Enumerate,
                        &[bucket_entry.as_bytes()],
                        stats,
                        &format!("receipts/{bucket_name}"),
                    ) {
                        return;
                    }
                    continue;
                }
            };
            shard_dirs.sort();

            for shard_entry in &shard_dirs {
                // Entry level cursor: skip shards before cursor when bucket matches.
                if let Some(cursor) = &self.recovery_cursor.compact_receipts {
                    if bucket_entry.as_bytes() == cursor.first
                        && shard_entry.as_bytes() < cursor.second.as_slice()
                    {
                        continue;
                    }
                }
                let Some(shard_name) = shard_entry.as_ascii_str() else {
                    Self::record_error(
                        stats,
                        "compact_shard_name",
                        &raw_name_for_error(shard_entry),
                        "shard directory name is not ASCII",
                    );
                    continue;
                };
                let Some(shard) = steadq_names::shard_from_hex(shard_name) else {
                    Self::record_error(
                        stats,
                        "compact_shard_name",
                        shard_name,
                        "shard directory name is not canonical",
                    );
                    continue;
                };
                if shard >= self.format.shard_count() {
                    Self::record_error(
                        stats,
                        "compact_shard_name",
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
                            "compact_shard_open",
                            &format!("receipts/{bucket_name}/{shard_name}"),
                            &error.to_string(),
                        );
                        if !self.remember_hierarchy_retry_or_block(
                            RecoveryPhase::CompactReceipts,
                            RecoveryHierarchyRetryKind::Open,
                            &[bucket_entry.as_bytes(), shard_entry.as_bytes()],
                            stats,
                            &format!("receipts/{bucket_name}/{shard_name}"),
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
                            "compact_entry_read",
                            &format!("receipts/{bucket_name}/{shard_name}"),
                            &error,
                        ) {
                            return;
                        }
                        if !self.remember_hierarchy_retry_or_block(
                            RecoveryPhase::CompactReceipts,
                            RecoveryHierarchyRetryKind::Enumerate,
                            &[bucket_entry.as_bytes(), shard_entry.as_bytes()],
                            stats,
                            &format!("receipts/{bucket_name}/{shard_name}"),
                        ) {
                            return;
                        }
                        continue;
                    }
                };
                entries.sort();

                for raw_entry in &entries {
                    // Entry level cursor: skip entries at or before cursor when bucket and shard match.
                    if let Some(cursor) = &self.recovery_cursor.compact_receipts {
                        if cursor.should_skip(
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
                    self.recovery_cursor.compact_receipts = Some(ThreeLevelCursor::new(
                        bucket_entry.as_bytes(),
                        shard_entry.as_bytes(),
                        raw_entry.as_bytes(),
                    ));
                    let Some(entry) = raw_entry.as_ascii_str() else {
                        Self::record_error(
                            stats,
                            "compact_entry_name",
                            &raw_name_for_error(raw_entry),
                            "entry name is not ASCII",
                        );
                        continue;
                    };

                    if compaction_temporary_name(entry) {
                        let temp_path = format!("receipts/{bucket_name}/{shard_name}/{entry}");
                        stats.operations_attempted += 1;
                        if let Err(failure) = unlink_verified(shard_fd.as_fd(), entry) {
                            Self::record_unlink_failure(
                                stats,
                                "receipt_compact_stale_temp_cleanup",
                                &temp_path,
                                failure,
                            );
                        }
                        continue;
                    }

                    if !entry.ends_with(".rct") {
                        continue;
                    }

                    let receipt_fd = match open_locked_receipt(shard_fd.as_fd(), entry) {
                        Ok(Some(fd)) => fd,
                        Ok(None) => continue,
                        Err(error) => {
                            let operation = error.operation("receipt_compact");
                            Self::record_error(
                                stats,
                                &operation,
                                &format!("receipts/{bucket_name}/{shard_name}/{entry}"),
                                &error.to_string(),
                            );
                            continue;
                        }
                    };

                    let verified_receipt = match crate::queue::verified::verify_receipt_on_fd(
                        receipt_fd.as_fd(),
                        crate::queue::verified::ReceiptContext {
                            queue_id: self.format.queue_id(),
                            shard_count: self.format.shard_count(),
                            terminal_bucket_width_ns: self.format.terminal_bucket_width_ns(),
                            max_payload_length: self.format.max_payload_length(),
                            bucket: bucket_name,
                            shard: shard_name,
                            filename: entry,
                        },
                        None,
                    ) {
                        Ok(receipt) => receipt,
                        Err(error) => {
                            Self::record_error(
                                stats,
                                "receipt_compact_invalid",
                                &format!("receipts/{bucket_name}/{shard_name}/{entry}"),
                                &error.to_string(),
                            );
                            continue;
                        }
                    };

                    let crate::queue::verified::VerifiedReceipt {
                        name: parsed,
                        bucket_number,
                        kind,
                        device,
                        inode,
                    } = verified_receipt;
                    let header = match kind {
                        crate::queue::verified::VerifiedReceiptKind::Full(job) => {
                            job.header().clone()
                        }
                        crate::queue::verified::VerifiedReceiptKind::Compact => continue,
                    };
                    let bucket_start =
                        match bucket_number.checked_mul(self.format.terminal_bucket_width_ns()) {
                            Some(bucket_start) => bucket_start,
                            None => continue,
                        };

                    // Build compact receipt
                    let compact = steadq_format::CompactReceipt {
                        job_id: header.job_id,
                        envelope_digest: header.envelope_digest,
                        final_attempt: parsed.common.attempt,
                        lease_token: parsed.token,
                        receipt_bucket_start_unix_ns: bucket_start,
                        original_payload_length: header.payload_length,
                    };

                    let compact_bytes = compact.encode();
                    let receipt_path = format!("receipts/{bucket_name}/{shard_name}/{entry}");

                    stats.operations_attempted += 1;
                    let random = match steadq_fs_linux::random_128bit() {
                        Ok(random) => random,
                        Err(error) => {
                            Self::record_error(
                                stats,
                                "receipt_compact_temp_name_not_committed",
                                &receipt_path,
                                &format!("phase=TempName: {error}"),
                            );
                            continue;
                        }
                    };

                    // Write to a temp file in the same directory
                    let tmp_name = format!(
                        ".compact-{}.tmp",
                        random
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<String>()
                    );

                    let temp_path = format!("receipts/{bucket_name}/{shard_name}/{tmp_name}");

                    let tmp_fd = match fs::create_exclusive(shard_fd.as_fd(), &tmp_name, 0o600) {
                        Ok(fd) => fd,
                        Err(error) => {
                            Self::record_error(
                                stats,
                                "receipt_compact_temp_create_not_committed",
                                &temp_path,
                                &format!("phase=TempCreate: {error}"),
                            );
                            continue;
                        }
                    };

                    if let Err(error) = fs::write_all(tmp_fd.as_fd(), &compact_bytes) {
                        Self::record_error(
                            stats,
                            "receipt_compact_temp_write_not_committed",
                            &temp_path,
                            &format!("phase=TempWrite: {error}"),
                        );
                        Self::cleanup_compaction_temp(
                            stats,
                            shard_fd.as_fd(),
                            &tmp_name,
                            &temp_path,
                        );
                        continue;
                    }
                    if let Err(error) = fs::fsync(tmp_fd.as_fd()) {
                        Self::record_error(
                            stats,
                            "receipt_compact_temp_fsync_not_committed",
                            &temp_path,
                            &format!("phase=TempFsync: {error}"),
                        );
                        Self::cleanup_compaction_temp(
                            stats,
                            shard_fd.as_fd(),
                            &tmp_name,
                            &temp_path,
                        );
                        continue;
                    }

                    // Replace the original with the compact version
                    match replace_verified(
                        shard_fd.as_fd(),
                        &tmp_name,
                        shard_fd.as_fd(),
                        entry,
                        Some(ReplaceIdentity::new(device, inode)),
                    ) {
                        Ok(()) => stats.receipts_compacted += 1,
                        Err(failure) => {
                            let source_missing = matches!(failure, ReplaceFailure::SourceMissing);
                            let outcome_unknown = failure.is_outcome_unknown();
                            Self::record_replace_failure(
                                stats,
                                "receipt_compact_replace",
                                &receipt_path,
                                failure,
                            );
                            if !outcome_unknown || source_missing {
                                Self::cleanup_compaction_temp(
                                    stats,
                                    shard_fd.as_fd(),
                                    &tmp_name,
                                    &temp_path,
                                );
                            }
                        }
                    }
                }
            }
        }

        // All buckets processed, reset cursor for next full pass.
        self.recovery_cursor.compact_receipts = None;
    }

    /// Delete expired receipts based on retention policy.
    pub(crate) fn delete_expired_receipts(
        &mut self,
        wall_floor: WallFloor,
        retention_ns: u64,
        budget: &WorkBudget,
        scan: &mut RecoveryScanContext<'_>,
        stats: &mut RecoveryStats,
        deadline_mono: u64,
    ) {
        let root_fd = self.root_fd();
        let wall_floor = wall_floor.unix_ns();

        let receipts_fd = match fs::open_directory(root_fd, "receipts") {
            Ok(fd) => fd,
            Err(error) => {
                Self::block_phase(stats, "delete_root_open", "receipts", &error.to_string());
                return;
            }
        };
        let hierarchy_retry = self.prepare_hierarchy_retry_phase(RecoveryPhase::DeleteReceipts);
        if self.retry_one_hierarchy_directory(
            RecoveryPhase::DeleteReceipts,
            hierarchy_retry,
            receipts_fd.as_fd(),
            scan,
            stats,
            deadline_mono,
        ) {
            return;
        }

        let mut bucket_dirs = match read_recovery_directory(
            receipts_fd.as_fd(),
            deadline_mono,
            scan.budget,
            scan.stats,
        ) {
            Ok(e) => e,
            Err(error) => {
                Self::record_directory_error(stats, "delete_bucket_read", "receipts", &error);
                return;
            }
        };
        bucket_dirs.sort();

        for bucket_entry in &bucket_dirs {
            // Skip buckets already processed in a prior pass.
            if let Some(cursor) = &self.recovery_cursor.delete_receipts {
                if bucket_entry.as_bytes() < cursor.first.as_slice() {
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
                    "delete_bucket_name",
                    &raw_name_for_error(bucket_entry),
                    "bucket directory name is not ASCII",
                );
                continue;
            };

            let bucket_num = match steadq_names::bucket_from_hex(bucket_name) {
                Some(bucket) => bucket,
                None => {
                    Self::record_error(
                        stats,
                        "delete_bucket_name",
                        bucket_name,
                        "bucket directory name is not canonical",
                    );
                    continue;
                }
            };

            let bucket_start = match bucket_num.checked_mul(self.format.terminal_bucket_width_ns())
            {
                Some(s) => s,
                None => continue,
            };
            let bucket_end = match bucket_start.checked_add(self.format.terminal_bucket_width_ns())
            {
                Some(e) => e,
                None => continue,
            };

            // Check retention: bucket_end + retention <= wall_floor
            let eligible = match bucket_end.checked_add(retention_ns) {
                Some(threshold) => threshold <= wall_floor,
                None => false,
            };

            if !eligible {
                continue;
            }

            let bucket_fd = match fs::open_directory(receipts_fd.as_fd(), bucket_name) {
                Ok(fd) => fd,
                Err(error) => {
                    stats.scan_skips += 1;
                    Self::block_phase(
                        stats,
                        "delete_bucket_open",
                        &format!("receipts/{bucket_name}"),
                        &error.to_string(),
                    );
                    if !self.remember_hierarchy_retry_or_block(
                        RecoveryPhase::DeleteReceipts,
                        RecoveryHierarchyRetryKind::Open,
                        &[bucket_entry.as_bytes()],
                        stats,
                        &format!("receipts/{bucket_name}"),
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
                        "delete_shard_read",
                        &format!("receipts/{bucket_name}"),
                        &error,
                    ) {
                        return;
                    }
                    if !self.remember_hierarchy_retry_or_block(
                        RecoveryPhase::DeleteReceipts,
                        RecoveryHierarchyRetryKind::Enumerate,
                        &[bucket_entry.as_bytes()],
                        stats,
                        &format!("receipts/{bucket_name}"),
                    ) {
                        return;
                    }
                    continue;
                }
            };
            shard_dirs.sort();
            let mut absent_shards = 0usize;

            for shard_entry in &shard_dirs {
                // Entry level cursor: skip shards before cursor when bucket matches.
                if let Some(cursor) = &self.recovery_cursor.delete_receipts {
                    if bucket_entry.as_bytes() == cursor.first
                        && shard_entry.as_bytes() < cursor.second.as_slice()
                    {
                        continue;
                    }
                }
                let Some(shard_name) = shard_entry.as_ascii_str() else {
                    Self::record_error(
                        stats,
                        "delete_shard_name",
                        &raw_name_for_error(shard_entry),
                        "shard directory name is not ASCII",
                    );
                    continue;
                };
                let Some(shard) = steadq_names::shard_from_hex(shard_name) else {
                    Self::record_error(
                        stats,
                        "delete_shard_name",
                        shard_name,
                        "shard directory name is not canonical",
                    );
                    continue;
                };
                if shard >= self.format.shard_count() {
                    Self::record_error(
                        stats,
                        "delete_shard_name",
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
                            "delete_shard_open",
                            &format!("receipts/{bucket_name}/{shard_name}"),
                            &error.to_string(),
                        );
                        if !self.remember_hierarchy_retry_or_block(
                            RecoveryPhase::DeleteReceipts,
                            RecoveryHierarchyRetryKind::Open,
                            &[bucket_entry.as_bytes(), shard_entry.as_bytes()],
                            stats,
                            &format!("receipts/{bucket_name}/{shard_name}"),
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
                            "delete_entry_read",
                            &format!("receipts/{bucket_name}/{shard_name}"),
                            &error,
                        ) {
                            return;
                        }
                        if !self.remember_hierarchy_retry_or_block(
                            RecoveryPhase::DeleteReceipts,
                            RecoveryHierarchyRetryKind::Enumerate,
                            &[bucket_entry.as_bytes(), shard_entry.as_bytes()],
                            stats,
                            &format!("receipts/{bucket_name}/{shard_name}"),
                        ) {
                            return;
                        }
                        continue;
                    }
                };
                entries.sort();
                let mut absent_entries = 0usize;

                for raw_entry in &entries {
                    // Entry level cursor: skip entries at or before cursor when bucket and shard match.
                    if let Some(cursor) = &self.recovery_cursor.delete_receipts {
                        if cursor.should_skip(
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
                    let previous_entry_cursor = self.recovery_cursor.delete_receipts.clone();
                    self.recovery_cursor.delete_receipts = Some(ThreeLevelCursor::new(
                        bucket_entry.as_bytes(),
                        shard_entry.as_bytes(),
                        raw_entry.as_bytes(),
                    ));
                    let Some(entry) = raw_entry.as_ascii_str() else {
                        Self::record_error(
                            stats,
                            "delete_entry_name",
                            &raw_name_for_error(raw_entry),
                            "entry name is not ASCII",
                        );
                        continue;
                    };
                    // Only process receipt files.
                    if !entry.ends_with(".rct") {
                        continue;
                    }
                    // A receipt name that does not parse can never pass the
                    // retention check, so it is quarantined like any other
                    // malformed object instead of staying forever.
                    if steadq_names::parse_receipt(entry).is_err() {
                        let relative_path = format!("receipts/{bucket_name}/{shard_name}/{entry}");
                        Self::record_error(
                            stats,
                            "receipt_delete_parse",
                            &relative_path,
                            "receipt filename does not parse",
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
                            self.recovery_cursor.delete_receipts = previous_entry_cursor;
                            return;
                        }
                        continue;
                    }

                    let receipt_fd = match open_locked_receipt(shard_fd.as_fd(), entry) {
                        Ok(Some(fd)) => fd,
                        Ok(None) => continue,
                        Err(error) => {
                            let operation = error.operation("receipt_delete");
                            Self::record_error(
                                stats,
                                &operation,
                                &format!("receipts/{bucket_name}/{shard_name}/{entry}"),
                                &error.to_string(),
                            );
                            continue;
                        }
                    };

                    let verified_receipt = match crate::queue::verified::verify_receipt_on_fd(
                        receipt_fd.as_fd(),
                        crate::queue::verified::ReceiptContext {
                            queue_id: self.format.queue_id(),
                            shard_count: self.format.shard_count(),
                            terminal_bucket_width_ns: self.format.terminal_bucket_width_ns(),
                            max_payload_length: self.format.max_payload_length(),
                            bucket: bucket_name,
                            shard: shard_name,
                            filename: entry,
                        },
                        None,
                    ) {
                        Ok(receipt) => receipt,
                        Err(error) => {
                            Self::record_error(
                                stats,
                                "receipt_delete_invalid",
                                &format!("receipts/{bucket_name}/{shard_name}/{entry}"),
                                &error.to_string(),
                            );
                            continue;
                        }
                    };
                    let current = match fs::fstatat(shard_fd.as_fd(), entry) {
                        Ok(stat) => stat,
                        Err(_) => continue,
                    };
                    if !crate::queue::verified::receipt_path_identity_matches(
                        &current,
                        verified_receipt.device,
                        verified_receipt.inode,
                    ) {
                        Self::record_error(
                            stats,
                            "receipt_delete_replaced",
                            &format!("receipts/{bucket_name}/{shard_name}/{entry}"),
                            "receipt pathname changed after verification",
                        );
                        continue;
                    }

                    stats.operations_attempted += 1;
                    let relative_path = format!("receipts/{bucket_name}/{shard_name}/{entry}");
                    match unlink_verified(shard_fd.as_fd(), entry) {
                        Ok(()) => {
                            stats.receipts_expired += 1;
                            absent_entries += 1;
                        }
                        Err(UnlinkFailure::SourceMissing) => {
                            absent_entries += 1;
                            Self::record_unlink_failure(
                                stats,
                                "receipt_delete",
                                &relative_path,
                                UnlinkFailure::SourceMissing,
                            );
                        }
                        Err(failure) => Self::record_unlink_failure(
                            stats,
                            "receipt_delete",
                            &relative_path,
                            failure,
                        ),
                    }
                }

                if !all_observed_children_absent(absent_entries, entries.len()) {
                    continue;
                }
                if Self::work_budget_exhausted(stats, budget, deadline_mono) {
                    stats.budget_exhausted = true;
                    return;
                }
                stats.operations_attempted += 1;
                let shard_path = format!("receipts/{bucket_name}/{shard_name}");
                match remove_empty_directory_verified(bucket_fd.as_fd(), shard_name) {
                    Ok(()) => {
                        stats.shards_removed += 1;
                        absent_shards += 1;
                    }
                    Err(RemoveDirectoryFailure::SourceMissing) => absent_shards += 1,
                    Err(RemoveDirectoryFailure::NotEmpty) => {}
                    Err(failure) => Self::record_remove_directory_failure(
                        stats,
                        "receipt_shard_remove",
                        &shard_path,
                        failure,
                    ),
                }
            }

            if !all_observed_children_absent(absent_shards, shard_dirs.len()) {
                continue;
            }
            if Self::work_budget_exhausted(stats, budget, deadline_mono) {
                stats.budget_exhausted = true;
                return;
            }
            stats.operations_attempted += 1;
            let bucket_path = format!("receipts/{bucket_name}");
            match remove_empty_directory_verified(receipts_fd.as_fd(), bucket_name) {
                Ok(()) => stats.buckets_removed += 1,
                Err(RemoveDirectoryFailure::SourceMissing | RemoveDirectoryFailure::NotEmpty) => {}
                Err(failure) => Self::record_remove_directory_failure(
                    stats,
                    "receipt_bucket_remove",
                    &bucket_path,
                    failure,
                ),
            }
        }

        // All buckets processed, reset cursor for next full pass.
        self.recovery_cursor.delete_receipts = None;
    }
}

enum ReceiptPrepareError {
    Open(io::Error),
    Lock(io::Error),
}

impl ReceiptPrepareError {
    fn operation(&self, prefix: &str) -> String {
        match self {
            Self::Open(_) => format!("{prefix}_open"),
            Self::Lock(_) => format!("{prefix}_lock"),
        }
    }
}

impl std::fmt::Display for ReceiptPrepareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open(error) | Self::Lock(error) => write!(f, "{error}"),
        }
    }
}

/// Open a receipt and take an OFD write lock. Missing files and busy locks skip.
/// Open or lock I/O errors are returned so the caller can record them.
fn open_locked_receipt(
    dir_fd: BorrowedFd<'_>,
    name: &str,
) -> Result<Option<OwnedFd>, ReceiptPrepareError> {
    let fd = match fs::openat(
        dir_fd,
        name,
        crate::queue::verified::receipt_write_open_flags(),
        0,
    ) {
        Ok(fd) => fd,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(ReceiptPrepareError::Open(error)),
    };
    match fs::try_ofd_write_lock(fd.as_fd()) {
        Ok(true) => Ok(Some(fd)),
        Ok(false) => Ok(None),
        Err(error) => Err(ReceiptPrepareError::Lock(error)),
    }
}
