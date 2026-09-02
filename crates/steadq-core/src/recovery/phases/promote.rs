// Delayed-to-ready promotion.
use super::*;

impl Queue {
    pub(crate) fn promote_delayed(
        &mut self,
        wall_floor: WallFloor,
        budget: &WorkBudget,
        scan: &mut RecoveryScanContext<'_>,
        stats: &mut RecoveryStats,
        deadline_mono: u64,
    ) {
        let root_fd = self.root_fd();
        let delayed_fd = match fs::open_directory(root_fd, "delayed") {
            Ok(fd) => fd,
            Err(error) => {
                Self::block_phase(stats, "promote_root_open", "delayed", &error.to_string());
                return;
            }
        };
        let hierarchy_retry = self.prepare_hierarchy_retry_phase(RecoveryPhase::PromoteDelayed);
        if self.retry_one_hierarchy_directory(
            RecoveryPhase::PromoteDelayed,
            hierarchy_retry,
            delayed_fd.as_fd(),
            scan,
            stats,
            deadline_mono,
        ) {
            return;
        }

        let mut bucket_dirs = match read_recovery_directory(
            delayed_fd.as_fd(),
            deadline_mono,
            scan.budget,
            scan.stats,
        ) {
            Ok(e) => e,
            Err(error) => {
                Self::record_directory_error(stats, "promote_bucket_read", "delayed", &error);
                return;
            }
        };
        bucket_dirs.sort();

        // Only buckets at or below the current wall bucket are promoted.
        let Some(current_wall_bucket) =
            steadq_math::bucket_number(wall_floor.unix_ns(), self.format.delayed_bucket_width_ns())
        else {
            Self::block_phase(
                stats,
                "promote_wall_bucket",
                "delayed",
                "wall floor has no delayed bucket",
            );
            return;
        };

        for bucket_entry in &bucket_dirs {
            // Skip buckets already processed in a prior pass.
            if let Some(cursor) = &self.recovery_cursor.promote_delayed {
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
                    "promote_bucket_name",
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
                        "promote_bucket_name",
                        bucket_name,
                        "bucket directory name is not canonical",
                    );
                    continue;
                }
            };

            // Only promote buckets at or below the current wall bucket
            if bucket_num > current_wall_bucket {
                continue;
            }

            let bucket_fd = match fs::open_directory(delayed_fd.as_fd(), bucket_name) {
                Ok(fd) => fd,
                Err(error) => {
                    stats.scan_skips += 1;
                    Self::block_phase(
                        stats,
                        "promote_bucket_open",
                        &format!("delayed/{bucket_name}"),
                        &error.to_string(),
                    );
                    if !self.remember_hierarchy_retry_or_block(
                        RecoveryPhase::PromoteDelayed,
                        RecoveryHierarchyRetryKind::Open,
                        &[bucket_entry.as_bytes()],
                        stats,
                        &format!("delayed/{bucket_name}"),
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
                        "promote_shard_read",
                        &format!("delayed/{bucket_name}"),
                        &error,
                    ) {
                        return;
                    }
                    if !self.remember_hierarchy_retry_or_block(
                        RecoveryPhase::PromoteDelayed,
                        RecoveryHierarchyRetryKind::Enumerate,
                        &[bucket_entry.as_bytes()],
                        stats,
                        &format!("delayed/{bucket_name}"),
                    ) {
                        return;
                    }
                    continue;
                }
            };
            shard_dirs.sort();

            for shard_entry in &shard_dirs {
                // Entry level cursor: skip shards before cursor when bucket matches.
                if let Some(cursor) = &self.recovery_cursor.promote_delayed {
                    if bucket_entry.as_bytes() == cursor.first
                        && shard_entry.as_bytes() < cursor.second.as_slice()
                    {
                        continue;
                    }
                }
                let Some(shard_name) = shard_entry.as_ascii_str() else {
                    Self::record_error(
                        stats,
                        "promote_shard_name",
                        &raw_name_for_error(shard_entry),
                        "shard directory name is not ASCII",
                    );
                    continue;
                };
                let Some(shard) = steadq_names::shard_from_hex(shard_name) else {
                    Self::record_error(
                        stats,
                        "promote_shard_name",
                        shard_name,
                        "shard directory name is not canonical",
                    );
                    continue;
                };
                if shard >= self.format.shard_count() {
                    Self::record_error(
                        stats,
                        "promote_shard_name",
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
                            "promote_shard_open",
                            &format!("{bucket_name}/{shard_name}"),
                            &error.to_string(),
                        );
                        if !self.remember_hierarchy_retry_or_block(
                            RecoveryPhase::PromoteDelayed,
                            RecoveryHierarchyRetryKind::Open,
                            &[bucket_entry.as_bytes(), shard_entry.as_bytes()],
                            stats,
                            &format!("delayed/{bucket_name}/{shard_name}"),
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
                            "promote_entry_read",
                            &format!("delayed/{bucket_name}/{shard_name}"),
                            &error,
                        ) {
                            return;
                        }
                        if !self.remember_hierarchy_retry_or_block(
                            RecoveryPhase::PromoteDelayed,
                            RecoveryHierarchyRetryKind::Enumerate,
                            &[bucket_entry.as_bytes(), shard_entry.as_bytes()],
                            stats,
                            &format!("delayed/{bucket_name}/{shard_name}"),
                        ) {
                            return;
                        }
                        continue;
                    }
                };
                entries.sort();

                for raw_entry in &entries {
                    // Entry level cursor: skip entries at or before cursor when bucket and shard match.
                    if let Some(cursor) = &self.recovery_cursor.promote_delayed {
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
                    let previous_entry_cursor = self.recovery_cursor.promote_delayed.clone();
                    self.recovery_cursor.promote_delayed = Some(ThreeLevelCursor::new(
                        bucket_entry.as_bytes(),
                        shard_entry.as_bytes(),
                        raw_entry.as_bytes(),
                    ));
                    let Some(entry) = raw_entry.as_ascii_str() else {
                        Self::record_error(
                            stats,
                            "promote_entry_name",
                            &raw_name_for_error(raw_entry),
                            "entry name is not ASCII",
                        );
                        continue;
                    };

                    if !entry.ends_with(".sqj") {
                        continue;
                    }

                    let parsed = match steadq_names::parse_delayed(entry) {
                        Ok(p) => p,
                        Err(_) => {
                            let relative_path =
                                format!("delayed/{bucket_name}/{shard_name}/{entry}");
                            Self::record_error(
                                stats,
                                "promote_parse",
                                &relative_path,
                                "malformed delayed filename",
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
                                self.recovery_cursor.promote_delayed = previous_entry_cursor;
                                return;
                            }
                            continue;
                        }
                    };

                    // Validate object structure before promotion
                    {
                        let delayed_ctx = crate::ActivePathContext::Delayed {
                            bucket: bucket_name.to_string(),
                            shard: shard_name.to_string(),
                        };
                        if let Err(e) =
                            self.validate_active_object(shard_fd.as_fd(), entry, &delayed_ctx)
                        {
                            Self::record_error(
                                stats,
                                "promote_validate",
                                &format!("delayed/{bucket_name}/{shard_name}/{entry}"),
                                &format!("{e}"),
                            );
                            if matches!(e, Error::QueueCorrupt(_))
                                && !self.quarantine_recovery_object(
                                    RecoveryQuarantineCandidate {
                                        source_directory_fd: shard_fd.as_fd(),
                                        filename: entry,
                                        relative_path: &format!(
                                            "delayed/{bucket_name}/{shard_name}/{entry}"
                                        ),
                                        reason: crate::QuarantineReason::EnvelopeCorrupt,
                                    },
                                    stats,
                                    budget,
                                )
                            {
                                self.recovery_cursor.promote_delayed = previous_entry_cursor;
                                return;
                            }
                            continue;
                        }
                    }

                    stats.operations_attempted += 1;
                    let relative_path = format!("delayed/{bucket_name}/{shard_name}/{entry}");
                    match self.promote_to_ready(shard_fd.as_fd(), shard_name, entry, &parsed.common)
                    {
                        Ok(()) => stats.delayed_promoted += 1,
                        Err(failure) => Self::record_move_failure(
                            stats,
                            "promote_delayed",
                            &relative_path,
                            failure,
                        ),
                    }
                }
            }
        }

        // All buckets processed, reset cursor for next full pass.
        self.recovery_cursor.promote_delayed = None;
    }

    pub(crate) fn promote_to_ready(
        &self,
        src_fd: BorrowedFd<'_>,
        shard: &str,
        delayed_name: &str,
        common: &steadq_names::CommonFields,
    ) -> Result<(), MoveFailure> {
        let ready_common =
            crate::next_common_fields(crate::state_machine::Operation::Promote, common).map_err(
                |_| MoveFailure::NotCommitted {
                    phase: MovePhase::PreRename,
                    source: std::io::Error::other("generation or attempt overflow"),
                },
            )?;
        let ready_name =
            steadq_names::make_ready_name(self.format.queue_id(), shard, &ready_common);
        let dest_dir = format!("ready/{shard}");
        let dest_fd = open_relative(self.root_fd(), &dest_dir).map_err(|error| {
            MoveFailure::NotCommitted {
                phase: MovePhase::EnsureDest,
                source: error,
            }
        })?;

        move_verified_noreplace(src_fd, delayed_name, dest_fd.as_fd(), &ready_name)
    }
}
