// Enqueue publication: buffered, streaming, and named-fallback.
use super::*;

impl Queue {
    pub fn enqueue(&mut self, job: EnqueueInput) -> EnqueueOutcome {
        if self.deferred_dir_sync {
            let mut tmp = self.dirty.replace(engine::DirtySet::new());
            let outcome = self.enqueue_with_dirty(job, Some(&mut tmp));
            let prev = self.dirty.replace(tmp);
            drop(prev);
            return match outcome {
                EnqueueOutcome::Committed(ticket) => EnqueueOutcome::Deferred(ticket),
                outcome => outcome,
            };
        }
        self.enqueue_inner(job)
    }

    fn enqueue_inner(&mut self, job: EnqueueInput) -> EnqueueOutcome {
        self.enqueue_with_dirty(job, None)
    }

    pub(super) fn enqueue_batched(
        &mut self,
        job: EnqueueInput,
        dirty: &mut engine::DirtySet,
    ) -> EnqueueOutcome {
        self.enqueue_with_dirty(job, Some(dirty))
    }

    fn prepare_enqueue(
        &mut self,
        job: EnqueueInput,
    ) -> Result<PreparedEnqueue, (EnqueueTicket, Error)> {
        if let Err(e) = self.check_not_poisoned() {
            return Err((EnqueueTicket::uncommitted([0; 16]), e));
        }
        let job_id = match fs::random_128bit() {
            Ok(id) => id,
            Err(e) => {
                return Err((EnqueueTicket::uncommitted([0; 16]), Error::from(e)));
            }
        };
        let wall_floor = match self.wall_floor_for_mutation() {
            Ok(floor) => floor,
            Err(error) => {
                return Err((EnqueueTicket::uncommitted(job_id), error));
            }
        };
        let created_at = wall_floor.unix_ns();
        if job.maximum_attempts == 0 {
            return Err((
                EnqueueTicket::uncommitted(job_id),
                Error::InvalidInput("maximum_attempts must be >= 1".into()),
            ));
        }
        let ext = ExtensionHeader {
            initial_not_before_unix_ns: job.initial_not_before,
            content_type: job.content_type.clone(),
            metadata: job.metadata.clone(),
            producer_id: job.producer_id.clone(),
            trace_context: job.trace_context.clone(),
        };
        let ext_bytes = match ext.encode() {
            Ok(b) => b,
            Err(e) => {
                return Err((
                    EnqueueTicket::uncommitted(job_id),
                    Error::InvalidInput(e.to_string()),
                ));
            }
        };
        if job.payload.len() as u64 > self.format.max_payload_length().min(MAX_PAYLOAD_LENGTH) {
            return Err((
                EnqueueTicket::uncommitted(job_id),
                Error::InvalidInput("payload exceeds limit".into()),
            ));
        }
        let pdig = payload_digest(&job.payload);
        let mut header = FixedHeader {
            format_minor: FORMAT_MINOR,
            extension_header_length: ext_bytes.len() as u32,
            payload_length: job.payload.len() as u64,
            flags: 0,
            digest_algorithm: DIGEST_ALGORITHM_SHA256,
            job_id,
            maximum_attempts: job.maximum_attempts,
            created_at_unix_ns: created_at,
            payload_digest: pdig,
            envelope_digest: [0; 32],
        };
        let env_dig = match envelope_digest(&header, &ext_bytes) {
            Some(d) => d,
            None => {
                return Err((
                    EnqueueTicket::uncommitted(job_id),
                    Error::InvalidInput("extension length mismatch".into()),
                ));
            }
        };
        header.envelope_digest = env_dig;
        let now_wall = wall_floor.unix_ns();
        let (initial_state, _) = match job.initial_not_before {
            Some(nb) if nb > now_wall => {
                let (eb, _) =
                    match eligibility_bucket_and_ns(nb, self.format.delayed_bucket_width_ns()) {
                        Some(v) => v,
                        None => {
                            let ticket = EnqueueTicket {
                                job_id,
                                envelope_digest: header.envelope_digest,
                                expected_initial_state: InitialState::Ready,
                                expected_relative_path: String::new(),
                            };
                            return Err((
                                ticket,
                                Error::InvalidInput("eligibility overflow".into()),
                            ));
                        }
                    };
                (InitialState::Delayed, eb)
            }
            _ => (InitialState::Ready, 0),
        };
        let origin = CommonFields {
            job_id,
            generation: 0,
            attempt: 0,
            maximum_attempts: job.maximum_attempts,
        };
        let enqueue_op = match initial_state {
            InitialState::Ready => ProtocolOperation::EnqueueImmediate,
            InitialState::Delayed => ProtocolOperation::EnqueueDelayed,
        };
        let common = match next_identity(enqueue_op, &origin) {
            Ok(common) => common,
            Err(error) => {
                return Err((EnqueueTicket::uncommitted(job_id), error));
            }
        };
        let (dest_dir_relative, filename, expected_path) = match initial_state {
            InitialState::Ready => {
                let target = self.layout().ready(&common);
                let path = target.relative_path();
                (target.directory(), target.filename, path)
            }
            InitialState::Delayed => {
                let Some(not_before_ns) = job.initial_not_before else {
                    return Err((
                        EnqueueTicket {
                            job_id,
                            envelope_digest: header.envelope_digest,
                            expected_initial_state: initial_state,
                            expected_relative_path: String::new(),
                        },
                        Error::QueueCorrupt("delayed enqueue lost its deadline".into()),
                    ));
                };
                let target = match self.layout().delayed(&common, not_before_ns) {
                    Ok(target) => target,
                    Err(error) => {
                        return Err((
                            EnqueueTicket {
                                job_id,
                                envelope_digest: header.envelope_digest,
                                expected_initial_state: initial_state,
                                expected_relative_path: String::new(),
                            },
                            error,
                        ));
                    }
                };
                let path = target.relative_path();
                (target.directory(), target.filename, path)
            }
        };
        let ticket = EnqueueTicket {
            job_id,
            envelope_digest: header.envelope_digest,
            expected_initial_state: initial_state,
            expected_relative_path: expected_path.clone(),
        };
        let ready_shard_hint = match initial_state {
            InitialState::Ready => Some(compute_shard(
                self.format.queue_id(),
                &job_id,
                self.format.shard_count(),
            )),
            InitialState::Delayed => None,
        };
        Ok(PreparedEnqueue {
            ticket,
            header,
            ext_bytes,
            payload: job.payload,
            dest_dir: dest_dir_relative,
            filename,
            ready_shard_hint,
        })
    }

    fn enqueue_with_dirty(
        &mut self,
        job: EnqueueInput,
        dirty: Option<&mut engine::DirtySet>,
    ) -> EnqueueOutcome {
        let prepared = match self.prepare_enqueue(job) {
            Ok(p) => p,
            Err((ticket, err)) => return EnqueueOutcome::NotCommitted(ticket, err),
        };
        let result = if let Some(d) = dirty {
            self.write_and_publish_with_dirty(
                &prepared.dest_dir,
                &prepared.filename,
                &prepared.header,
                &prepared.ext_bytes,
                &prepared.payload,
                Some(d),
            )
        } else {
            self.write_and_publish_with_dirty(
                &prepared.dest_dir,
                &prepared.filename,
                &prepared.header,
                &prepared.ext_bytes,
                &prepared.payload,
                None,
            )
        };
        match result {
            Ok(()) => {
                if let Some(shard) = prepared.ready_shard_hint {
                    self.ready_shard_hint = Some(shard);
                }
                EnqueueOutcome::Committed(prepared.ticket)
            }
            Err(PublishError::NotCommitted(e)) => EnqueueOutcome::NotCommitted(prepared.ticket, e),
            Err(PublishError::OutcomeUnknown(e)) => {
                self.poison(PoisonReason::PostLinearizationStateUnknown);
                EnqueueOutcome::OutcomeUnknown(prepared.ticket, e)
            }
            Err(PublishError::OutcomeUnknownPublished {
                envelope_digest,
                error,
            }) => {
                self.poison(PoisonReason::PostLinearizationStateUnknown);
                let mut ticket = prepared.ticket;
                ticket.envelope_digest = envelope_digest;
                EnqueueOutcome::OutcomeUnknown(ticket, error)
            }
        }
    }

    fn open_or_cache_dir(&mut self, relative: &str) -> io::Result<std::os::fd::OwnedFd> {
        if let Some((ref cached_path, ref cached_fd)) = self.cached_dest_fd {
            if cached_path == relative {
                // Re-open the cached fd to get a fresh OwnedFd (the caller needs its own).
                // dup is one syscall, cheaper than 2 openat calls.
                return cached_fd
                    .as_fd()
                    .try_clone_to_owned()
                    .map_err(|e| io::Error::other(e.to_string()));
            }
        }
        let fd = open_relative(self.root_fd.as_fd(), relative)?;
        self.cached_dest_fd = Some((
            relative.to_string(),
            fd.as_fd()
                .try_clone_to_owned()
                .map_err(|e| io::Error::other(e.to_string()))?,
        ));
        Ok(fd)
    }

    /// Flush all deferred directory fsync operations. Call this after a batch
    /// of operations when using deferred_dir_sync mode. This fsyncs the exact
    /// dirty directories that were recorded, deduplicated by device and inode.
    pub fn sync(&self) -> io::Result<()> {
        if self.deferred_dir_sync {
            let result = {
                let dirty = self.dirty.borrow();
                if dirty.is_empty() {
                    return Ok(());
                }
                dirty.sync_all()
            };
            if result.is_ok() {
                self.dirty.borrow_mut().clear();
            }
            return result;
        }
        for dir in [
            "ready",
            "leased",
            "delayed",
            "dead",
            "receipts",
            "quarantine",
            "control",
        ] {
            if let Ok(fd) = open_relative(self.root_fd.as_fd(), dir) {
                fs::fsync_dir_fd(fd.as_fd())?;
            }
        }
        fs::fsync_dir_fd(self.root_fd.as_fd())?;
        Ok(())
    }

    /// Strict group-commit batch. Operations are Pending until `commit` fsyncs
    /// every exact dirty directory once. If the barrier fails, post-linearization
    /// operations are OutcomeUnknown.
    pub fn batch(&mut self) -> Batch<'_> {
        Batch::new(self)
    }

    /// Write the job envelope to a temp file and publish via rename.
    fn write_and_publish_with_dirty(
        &mut self,
        dest_dir_relative: &str,
        dest_name: &str,
        header: &FixedHeader,
        ext_bytes: &[u8],
        payload: &[u8],
        mut dirty: Option<&mut engine::DirtySet>,
    ) -> Result<(), PublishError> {
        // Ensure destination directory exists
        if let Some(d) = dirty.as_deref_mut() {
            self.ensure_dir_with_dirty(dest_dir_relative, Some(d))
                .map_err(|e| PublishError::NotCommitted(Error::from(e)))?;
        } else {
            self.ensure_dir(dest_dir_relative)
                .map_err(|e| PublishError::NotCommitted(Error::from(e)))?;
        }

        let dest_fd = self
            .open_or_cache_dir(dest_dir_relative)
            .map_err(|e| PublishError::NotCommitted(Error::from(e)))?;

        if self.publication_mode == Some(fs::PublicationMode::NamedFallback) {
            return self.named_fallback_with_dirty(
                dest_dir_relative,
                dest_fd.as_fd(),
                dest_name,
                header,
                ext_bytes,
                payload,
                dirty,
            );
        }

        match fs::open_tmpfile(dest_fd.as_fd()) {
            Ok(tmp_fd) => {
                let header_bytes = header
                    .encode(ext_bytes)
                    .map_err(|e| PublishError::NotCommitted(Error::InvalidInput(e.to_string())))?;
                fs::writev_all(tmp_fd.as_fd(), &[&header_bytes, ext_bytes, payload])
                    .map_err(PublishError::classify_write)?;
                let publish_outcome = if dirty.is_some() {
                    engine::publish_tmpfile_noreplace_deferred_with_mode(
                        tmp_fd.as_fd(),
                        dest_fd.as_fd(),
                        dest_name,
                        self.publication_mode,
                    )
                } else {
                    engine::publish_tmpfile_noreplace_with_mode(
                        tmp_fd.as_fd(),
                        dest_fd.as_fd(),
                        dest_name,
                        self.publication_mode,
                    )
                };
                match publish_outcome {
                    Ok(engine::TmpfilePublishOutcome::Published(mode)) => {
                        self.publication_mode = Some(mode);
                        if let Some(d) = dirty {
                            d.record(dest_fd.as_fd())
                                .map_err(|e| PublishError::OutcomeUnknown(Error::from(e)))?;
                        }
                        Ok(())
                    }
                    Ok(engine::TmpfilePublishOutcome::Unsupported) => {
                        self.publication_mode = Some(fs::PublicationMode::NamedFallback);
                        self.named_fallback_with_dirty(
                            dest_dir_relative,
                            dest_fd.as_fd(),
                            dest_name,
                            header,
                            ext_bytes,
                            payload,
                            dirty,
                        )
                    }
                    Err(failure) => Err(PublishError::classify_tmpfile(failure)),
                }
            }
            Err(e) => {
                if engine::is_tmpfile_open_unsupported(&e) {
                    self.publication_mode = Some(fs::PublicationMode::NamedFallback);
                    self.named_fallback_with_dirty(
                        dest_dir_relative,
                        dest_fd.as_fd(),
                        dest_name,
                        header,
                        ext_bytes,
                        payload,
                        dirty,
                    )
                } else {
                    Err(PublishError::classify_write(e))
                }
            }
        }
    }

    /// Named temporary file fallback for enqueue.
    #[allow(clippy::too_many_arguments)]
    fn named_fallback_with_dirty(
        &self,
        dest_dir_relative: &str,
        dest_fd: BorrowedFd<'_>,
        dest_name: &str,
        header: &FixedHeader,
        ext_bytes: &[u8],
        payload: &[u8],
        mut dirty: Option<&mut engine::DirtySet>,
    ) -> Result<(), PublishError> {
        let shard_part = dest_dir_relative.rsplit('/').next().unwrap_or("0000");
        let tmp_dir = format!("tmp/{}/{}", self.boot_id, shard_part);
        if let Some(d) = dirty.as_deref_mut() {
            self.ensure_dir_with_dirty(&tmp_dir, Some(d))
                .map_err(|e| PublishError::NotCommitted(Error::from(e)))?;
        } else {
            self.ensure_dir(&tmp_dir)
                .map_err(|e| PublishError::NotCommitted(Error::from(e)))?;
        }
        let tmp_dir_fd = open_relative(self.root_fd.as_fd(), &tmp_dir)
            .map_err(|e| PublishError::NotCommitted(Error::from(e)))?;
        let boottime =
            fs::clock_boottime_ns().map_err(|e| PublishError::NotCommitted(Error::from(e)))?;
        let random = fs::random_128bit().map_err(|e| PublishError::NotCommitted(Error::from(e)))?;
        let temp_name = temp_filename(boottime, &random);
        let tmp_file = fs::create_exclusive(tmp_dir_fd.as_fd(), &temp_name, 0o600)
            .map_err(|e| PublishError::NotCommitted(Error::from(e)))?;
        struct TempGuard<'a, 'fd> {
            dir_fd: BorrowedFd<'fd>,
            name: &'a str,
            armed: bool,
        }
        impl Drop for TempGuard<'_, '_> {
            fn drop(&mut self) {
                if self.armed {
                    let _ = fs::unlinkat(self.dir_fd, self.name);
                }
            }
        }
        let mut temp_guard = TempGuard {
            dir_fd: tmp_dir_fd.as_fd(),
            name: &temp_name,
            armed: true,
        };
        let header_bytes = header
            .encode(ext_bytes)
            .map_err(|e| PublishError::NotCommitted(Error::InvalidInput(e.to_string())))?;
        fs::write_all(tmp_file.as_fd(), &header_bytes).map_err(PublishError::classify_write)?;
        fs::write_all(tmp_file.as_fd(), ext_bytes).map_err(PublishError::classify_write)?;
        fs::write_all(tmp_file.as_fd(), payload).map_err(PublishError::classify_write)?;
        fs::fsync(tmp_file.as_fd()).map_err(PublishError::classify_pre_pub_fsync)?;
        let temp_stat = fs::fstat(tmp_file.as_fd()).map_err(PublishError::classify_write)?;
        if let Some(d) = dirty {
            match engine::move_witnessed_noreplace_deferred(
                tmp_dir_fd.as_fd(),
                &temp_name,
                dest_fd,
                dest_name,
                engine::MoveIdentity::new(temp_stat.st_dev, temp_stat.st_ino),
                |_moved| Ok(()),
            ) {
                Ok(_) => {
                    temp_guard.armed = false;
                    d.record(tmp_dir_fd.as_fd())
                        .map_err(|e| PublishError::OutcomeUnknown(Error::from(e)))?;
                    d.record(dest_fd)
                        .map_err(|e| PublishError::OutcomeUnknown(Error::from(e)))?;
                    Ok(())
                }
                Err(failure) => {
                    if failure.is_outcome_unknown() {
                        temp_guard.armed = false;
                    }
                    Err(PublishError::from_move_failure(failure))
                }
            }
        } else {
            match engine::move_witnessed_noreplace_io(
                tmp_dir_fd.as_fd(),
                &temp_name,
                dest_fd,
                dest_name,
                engine::MoveIdentity::new(temp_stat.st_dev, temp_stat.st_ino),
            ) {
                Ok(()) => {
                    temp_guard.armed = false;
                    Ok(())
                }
                Err(failure) => {
                    if failure.is_outcome_unknown() {
                        temp_guard.armed = false;
                    }
                    Err(PublishError::from_move_failure(failure))
                }
            }
        }
    }

    /// Create a directory path recursively, syncing parents.
    pub(crate) fn ensure_dir(&self, relative: &str) -> io::Result<()> {
        if self.known_dirs.borrow().contains(relative) {
            return Ok(());
        }
        if self.deferred_dir_sync {
            let mut dirty = self.dirty.borrow_mut();
            return self.ensure_dir_with_dirty(relative, Some(&mut dirty));
        }
        self.ensure_dir_with_dirty(relative, None)
    }

    pub(crate) fn ensure_dir_with_dirty(
        &self,
        relative: &str,
        mut dirty: Option<&mut engine::DirtySet>,
    ) -> io::Result<()> {
        if self.known_dirs.borrow().contains(relative) {
            return Ok(());
        }
        if let Some(bucket) = sharded_bucket_parent(relative, self.format.shard_count()) {
            return self.ensure_sharded_bucket_with_dirty(bucket, dirty);
        }
        let components: Vec<&str> = relative.split('/').filter(|s| !s.is_empty()).collect();
        let mut current = None::<OwnedFd>;

        for comp in components {
            let parent = current
                .as_ref()
                .map_or(self.root_fd.as_fd(), |directory| directory.as_fd());
            let was_created = fs::mkdirat_eexist_ok(parent, comp, 0o700)?;
            let child = fs::open_directory(parent, comp)?;
            if was_created {
                match &mut dirty {
                    Some(set) => set.record(parent)?,
                    None => fs::fsync_dir_fd(parent)?,
                }
            }
            current = Some(child);
        }
        self.known_dirs.borrow_mut().insert(relative.to_string());
        Ok(())
    }

    fn ensure_sharded_bucket_with_dirty(
        &self,
        bucket: &str,
        mut dirty: Option<&mut engine::DirtySet>,
    ) -> io::Result<()> {
        self.ensure_dir_with_dirty(bucket, dirty.as_deref_mut())?;
        let bucket_fd = open_relative(self.root_fd.as_fd(), bucket)?;
        let shard_count = self.format.shard_count();
        for shard in 0..shard_count {
            fs::mkdirat_eexist_ok(bucket_fd.as_fd(), &shard_hex(shard), 0o700)?;
        }
        match dirty {
            Some(set) => set.record(bucket_fd.as_fd())?,
            None => fs::fsync_dir_fd(bucket_fd.as_fd())?,
        }
        let mut known = self.known_dirs.borrow_mut();
        for shard in 0..shard_count {
            known.insert(format!("{bucket}/{}", shard_hex(shard)));
        }
        Ok(())
    }

    /// Enqueue a job from a streaming payload source. The payload is written
    /// to the temp file in 64 KiB chunks without buffering the full payload
    /// in memory. The header (including payload digest) is computed from the
    /// streamed bytes using a placeholder-then-pwrite strategy.
    #[allow(clippy::too_many_arguments)]
    pub fn enqueue_streaming(
        &mut self,
        maximum_attempts: u32,
        content_type: String,
        metadata: std::collections::BTreeMap<String, steadq_format::cbor::MetadataValue>,
        producer_id: Option<String>,
        trace_context: Option<Vec<u8>>,
        initial_not_before: Option<u64>,
        mut reader: impl std::io::Read,
    ) -> EnqueueOutcome {
        if let Err(e) = self.check_not_poisoned() {
            return EnqueueOutcome::NotCommitted(EnqueueTicket::uncommitted([0; 16]), e);
        }

        if maximum_attempts == 0 {
            return EnqueueOutcome::NotCommitted(
                EnqueueTicket::uncommitted([0; 16]),
                Error::InvalidInput("maximum_attempts must be >= 1".into()),
            );
        }

        let wall_floor = match self.wall_floor_for_mutation() {
            Ok(floor) => floor,
            Err(error) => {
                return EnqueueOutcome::NotCommitted(EnqueueTicket::uncommitted([0; 16]), error)
            }
        };
        let created_at = wall_floor.unix_ns();
        let job_id = match fs::random_128bit() {
            Ok(id) => id,
            Err(e) => {
                return EnqueueOutcome::NotCommitted(
                    EnqueueTicket::uncommitted([0; 16]),
                    Error::from(e),
                )
            }
        };

        let ext = ExtensionHeader {
            initial_not_before_unix_ns: initial_not_before,
            content_type,
            metadata,
            producer_id,
            trace_context,
        };
        let ext_bytes = match ext.encode() {
            Ok(b) => b,
            Err(e) => {
                return EnqueueOutcome::NotCommitted(
                    EnqueueTicket::uncommitted(job_id),
                    Error::InvalidInput(e.to_string()),
                )
            }
        };

        // Write placeholder header, extension, then stream payload while hashing.
        // After streaming, pwrite the real header at offset 0.
        let now_wall = wall_floor.unix_ns();
        let (expected_initial_state, _) = match initial_not_before {
            Some(nb) if nb > now_wall => (InitialState::Delayed, 0u64),
            _ => (InitialState::Ready, 0),
        };

        let origin = CommonFields {
            job_id,
            generation: 0,
            attempt: 0,
            maximum_attempts,
        };
        let enqueue_op = match expected_initial_state {
            InitialState::Ready => ProtocolOperation::EnqueueImmediate,
            InitialState::Delayed => ProtocolOperation::EnqueueDelayed,
        };
        let common = match next_identity(enqueue_op, &origin) {
            Ok(common) => common,
            Err(error) => {
                return EnqueueOutcome::NotCommitted(EnqueueTicket::uncommitted(job_id), error)
            }
        };
        let (dest_dir_relative, filename, expected_path) = match expected_initial_state {
            InitialState::Ready => {
                let target = self.layout().ready(&common);
                {
                    let d = target.directory();
                    let p = target.relative_path();
                    (d, target.filename, p)
                }
            }
            InitialState::Delayed => {
                let Some(not_before_ns) = initial_not_before else {
                    return EnqueueOutcome::NotCommitted(
                        EnqueueTicket::uncommitted(job_id),
                        Error::QueueCorrupt("delayed enqueue lost its deadline".into()),
                    );
                };
                let target = match self.layout().delayed(&common, not_before_ns) {
                    Ok(t) => t,
                    Err(e) => {
                        return EnqueueOutcome::NotCommitted(EnqueueTicket::uncommitted(job_id), e)
                    }
                };
                {
                    let d = target.directory();
                    let p = target.relative_path();
                    (d, target.filename, p)
                }
            }
        };

        let result = if self.deferred_dir_sync {
            let mut tmp = self.dirty.replace(engine::DirtySet::new());
            let result = self.stream_and_publish(
                &dest_dir_relative,
                &filename,
                job_id,
                maximum_attempts,
                created_at,
                &ext_bytes,
                &mut reader,
                Some(&mut tmp),
            );
            let prev = self.dirty.replace(tmp);
            drop(prev);
            result
        } else {
            self.stream_and_publish(
                &dest_dir_relative,
                &filename,
                job_id,
                maximum_attempts,
                created_at,
                &ext_bytes,
                &mut reader,
                None,
            )
        };

        let env_dig = match &result {
            Ok(d) => *d,
            Err(PublishError::NotCommitted(e)) => {
                return EnqueueOutcome::NotCommitted(
                    EnqueueTicket {
                        job_id,
                        envelope_digest: [0; 32],
                        expected_initial_state,
                        expected_relative_path: expected_path,
                    },
                    e.clone(),
                )
            }
            Err(PublishError::OutcomeUnknown(e)) => {
                self.poison(PoisonReason::PostLinearizationStateUnknown);
                return EnqueueOutcome::OutcomeUnknown(
                    EnqueueTicket {
                        job_id,
                        envelope_digest: [0; 32],
                        expected_initial_state,
                        expected_relative_path: expected_path,
                    },
                    e.clone(),
                );
            }
            Err(PublishError::OutcomeUnknownPublished {
                envelope_digest,
                error,
            }) => {
                self.poison(PoisonReason::PostLinearizationStateUnknown);
                return EnqueueOutcome::OutcomeUnknown(
                    EnqueueTicket {
                        job_id,
                        envelope_digest: *envelope_digest,
                        expected_initial_state,
                        expected_relative_path: expected_path,
                    },
                    error.clone(),
                );
            }
        };

        let ticket = EnqueueTicket {
            job_id,
            envelope_digest: env_dig,
            expected_initial_state,
            expected_relative_path: expected_path,
        };
        if self.deferred_dir_sync {
            EnqueueOutcome::Deferred(ticket)
        } else {
            EnqueueOutcome::Committed(ticket)
        }
    }

    /// Stream payload to a temp file while computing the digest, then publish.
    /// Returns the envelope digest on success.
    #[allow(clippy::too_many_arguments)]
    fn stream_and_publish(
        &mut self,
        dest_dir_relative: &str,
        dest_name: &str,
        job_id: [u8; 16],
        maximum_attempts: u32,
        created_at: u64,
        ext_bytes: &[u8],
        reader: &mut dyn std::io::Read,
        mut dirty: Option<&mut engine::DirtySet>,
    ) -> Result<[u8; 32], PublishError> {
        if let Some(d) = dirty.as_deref_mut() {
            self.ensure_dir_with_dirty(dest_dir_relative, Some(d))
                .map_err(|e| PublishError::NotCommitted(Error::from(e)))?;
        } else {
            self.ensure_dir(dest_dir_relative)
                .map_err(|e| PublishError::NotCommitted(Error::from(e)))?;
        }
        let dest_fd = open_relative(self.root_fd.as_fd(), dest_dir_relative)
            .map_err(|e| PublishError::NotCommitted(Error::from(e)))?;

        if self.publication_mode == Some(fs::PublicationMode::NamedFallback) {
            return self.named_fallback_streaming_init(
                dest_dir_relative,
                dest_fd.as_fd(),
                dest_name,
                job_id,
                maximum_attempts,
                created_at,
                ext_bytes,
                reader,
                dirty,
            );
        }

        match fs::open_tmpfile(dest_fd.as_fd()) {
            Ok(tmp_fd) => {
                let (payload_len, payload_digest) =
                    Self::stream_payload_to_fd(tmp_fd.as_fd(), ext_bytes, reader)?;

                // Validate payload size.
                if payload_len > self.format.max_payload_length().min(MAX_PAYLOAD_LENGTH) {
                    return Err(PublishError::NotCommitted(Error::InvalidInput(
                        "payload exceeds limit".into(),
                    )));
                }

                // Construct and pwrite the real header.
                let mut header = FixedHeader {
                    format_minor: FORMAT_MINOR,
                    extension_header_length: ext_bytes.len() as u32,
                    payload_length: payload_len,
                    flags: 0,
                    digest_algorithm: DIGEST_ALGORITHM_SHA256,
                    job_id,
                    maximum_attempts,
                    created_at_unix_ns: created_at,
                    payload_digest,
                    envelope_digest: [0; 32],
                };
                let env_dig = envelope_digest(&header, ext_bytes).ok_or_else(|| {
                    PublishError::NotCommitted(Error::InvalidInput(
                        "extension length mismatch".into(),
                    ))
                })?;
                header.envelope_digest = env_dig;
                let header_bytes = header
                    .encode(ext_bytes)
                    .map_err(|e| PublishError::NotCommitted(Error::InvalidInput(e.to_string())))?;
                fs::pwrite_all(tmp_fd.as_fd(), &header_bytes, 0)
                    .map_err(PublishError::classify_write)?;

                let publish_outcome = if dirty.is_some() {
                    engine::publish_tmpfile_noreplace_deferred_with_mode(
                        tmp_fd.as_fd(),
                        dest_fd.as_fd(),
                        dest_name,
                        self.publication_mode,
                    )
                } else {
                    engine::publish_tmpfile_noreplace_with_mode(
                        tmp_fd.as_fd(),
                        dest_fd.as_fd(),
                        dest_name,
                        self.publication_mode,
                    )
                };
                match publish_outcome {
                    Ok(engine::TmpfilePublishOutcome::Published(mode)) => {
                        self.publication_mode = Some(mode);
                        if let Some(d) = dirty {
                            d.record(dest_fd.as_fd()).map_err(|e| {
                                PublishError::OutcomeUnknownPublished {
                                    envelope_digest: env_dig,
                                    error: Error::from(e),
                                }
                            })?;
                        }
                    }
                    Ok(engine::TmpfilePublishOutcome::Unsupported) => {
                        self.publication_mode = Some(fs::PublicationMode::NamedFallback);
                        return self.named_fallback_streaming(
                            dest_dir_relative,
                            dest_fd.as_fd(),
                            dest_name,
                            &header,
                            ext_bytes,
                            tmp_fd.as_fd(),
                            payload_len,
                            dirty,
                        );
                    }
                    Err(failure) => {
                        return Err(
                            PublishError::classify_tmpfile(failure).with_published_digest(env_dig)
                        )
                    }
                }
                Ok(env_dig)
            }
            Err(e) => {
                if engine::is_tmpfile_open_unsupported(&e) {
                    self.publication_mode = Some(fs::PublicationMode::NamedFallback);
                    self.named_fallback_streaming_init(
                        dest_dir_relative,
                        dest_fd.as_fd(),
                        dest_name,
                        job_id,
                        maximum_attempts,
                        created_at,
                        ext_bytes,
                        reader,
                        dirty,
                    )
                } else {
                    Err(PublishError::classify_write(e))
                }
            }
        }
    }

    /// Stream payload to a temp fd: write placeholder header, extension, then
    /// payload chunks while hashing. Returns (payload_length, payload_digest).
    fn stream_payload_to_fd(
        fd: BorrowedFd<'_>,
        ext_bytes: &[u8],
        reader: &mut dyn std::io::Read,
    ) -> Result<(u64, [u8; 32]), PublishError> {
        // Placeholder header: 128 zero bytes.
        let placeholder = [0u8; 128];
        fs::write_all(fd, &placeholder).map_err(PublishError::classify_write)?;
        fs::write_all(fd, ext_bytes).map_err(PublishError::classify_write)?;

        let mut hasher = Sha256::new();
        let mut total: u64 = 0;
        let mut buf = vec![0u8; 65536];
        loop {
            let n = reader
                .read(&mut buf)
                .map_err(|e| PublishError::NotCommitted(Error::from(e)))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            fs::write_all(fd, &buf[..n]).map_err(PublishError::classify_write)?;
            total = total.checked_add(n as u64).ok_or_else(|| {
                PublishError::NotCommitted(Error::InvalidInput("payload length overflow".into()))
            })?;
        }
        Ok((total, hasher.finalize().into()))
    }

    /// Named fallback for streaming when O_TMPFILE is unsupported.
    /// Reads back from the O_TMPFILE fd and writes to a named temp file.
    #[allow(clippy::too_many_arguments)]
    fn named_fallback_streaming(
        &mut self,
        dest_dir_relative: &str,
        dest_fd: BorrowedFd<'_>,
        dest_name: &str,
        header: &FixedHeader,
        ext_bytes: &[u8],
        tmpfile_fd: BorrowedFd<'_>,
        payload_len: u64,
        mut dirty: Option<&mut engine::DirtySet>,
    ) -> Result<[u8; 32], PublishError> {
        // The tmpfile already has the full content (placeholder header + ext + payload).
        // We need a named temp file that we can publish via rename.
        let tmp_dir = format!("tmp/{}", self.boot_id);
        let shard_part = dest_dir_relative.rsplit('/').next().unwrap_or("0000");
        let tmp_shard_dir = format!("{tmp_dir}/{shard_part}");
        if let Some(d) = dirty.as_deref_mut() {
            self.ensure_dir_with_dirty(&tmp_shard_dir, Some(d))
                .map_err(|e| PublishError::NotCommitted(Error::from(e)))?;
        } else {
            self.ensure_dir(&tmp_shard_dir)
                .map_err(|e| PublishError::NotCommitted(Error::from(e)))?;
        }
        let tmp_dir_fd = open_relative(self.root_fd.as_fd(), &tmp_shard_dir)
            .map_err(|e| PublishError::NotCommitted(Error::from(e)))?;
        let boottime =
            fs::clock_boottime_ns().map_err(|e| PublishError::NotCommitted(Error::from(e)))?;
        let random = fs::random_128bit().map_err(|e| PublishError::NotCommitted(Error::from(e)))?;
        let temp_name = temp_filename(boottime, &random);

        let tmp_file = fs::create_exclusive(tmp_dir_fd.as_fd(), &temp_name, 0o600)
            .map_err(|e| PublishError::NotCommitted(Error::from(e)))?;

        // Write the real header to the named temp.
        let header_bytes = header
            .encode(ext_bytes)
            .map_err(|e| PublishError::NotCommitted(Error::InvalidInput(e.to_string())))?;
        fs::write_all(tmp_file.as_fd(), &header_bytes).map_err(PublishError::classify_write)?;
        fs::write_all(tmp_file.as_fd(), ext_bytes).map_err(PublishError::classify_write)?;

        // Copy payload from tmpfile_fd (offset 128 + ext_len) to named temp.
        let data_offset = (128 + ext_bytes.len()) as u64;
        let mut copied: u64 = 0;
        let mut buf = vec![0u8; 65536];
        while copied < payload_len {
            let to_read = (buf.len() as u64).min(payload_len - copied) as usize;
            let n = fs::pread(tmpfile_fd, &mut buf[..to_read], data_offset + copied)
                .map_err(|e| PublishError::NotCommitted(Error::from(e)))?;
            if n == 0 {
                break;
            }
            fs::write_all(tmp_file.as_fd(), &buf[..n]).map_err(PublishError::classify_write)?;
            copied += n as u64;
        }

        fs::fsync(tmp_file.as_fd()).map_err(PublishError::classify_pre_pub_fsync)?;

        let temp_stat = fs::fstat(tmp_file.as_fd()).map_err(PublishError::classify_write)?;
        self.finish_named_stream_publish(
            tmp_dir_fd.as_fd(),
            dest_fd,
            &temp_name,
            dest_name,
            engine::MoveIdentity::new(temp_stat.st_dev, temp_stat.st_ino),
            header.envelope_digest,
            dirty,
        )
    }

    /// Named fallback for streaming when O_TMPFILE open fails entirely.
    #[allow(clippy::too_many_arguments)]
    fn named_fallback_streaming_init(
        &mut self,
        dest_dir_relative: &str,
        dest_fd: BorrowedFd<'_>,
        dest_name: &str,
        job_id: [u8; 16],
        maximum_attempts: u32,
        created_at: u64,
        ext_bytes: &[u8],
        reader: &mut dyn std::io::Read,
        mut dirty: Option<&mut engine::DirtySet>,
    ) -> Result<[u8; 32], PublishError> {
        let tmp_dir = format!("tmp/{}", self.boot_id);
        let shard_part = dest_dir_relative.rsplit('/').next().unwrap_or("0000");
        let tmp_shard_dir = format!("{tmp_dir}/{shard_part}");
        if let Some(d) = dirty.as_deref_mut() {
            self.ensure_dir_with_dirty(&tmp_shard_dir, Some(d))
                .map_err(|e| PublishError::NotCommitted(Error::from(e)))?;
        } else {
            self.ensure_dir(&tmp_shard_dir)
                .map_err(|e| PublishError::NotCommitted(Error::from(e)))?;
        }
        let tmp_dir_fd = open_relative(self.root_fd.as_fd(), &tmp_shard_dir)
            .map_err(|e| PublishError::NotCommitted(Error::from(e)))?;
        let boottime =
            fs::clock_boottime_ns().map_err(|e| PublishError::NotCommitted(Error::from(e)))?;
        let random = fs::random_128bit().map_err(|e| PublishError::NotCommitted(Error::from(e)))?;
        let temp_name = temp_filename(boottime, &random);

        let tmp_file = fs::create_exclusive(tmp_dir_fd.as_fd(), &temp_name, 0o600)
            .map_err(|e| PublishError::NotCommitted(Error::from(e)))?;

        // Stream payload to named temp while hashing.
        // Write placeholder header first, then extension, then payload.
        // After streaming, pwrite real header.
        let (payload_len, payload_digest) =
            Self::stream_payload_to_fd(tmp_file.as_fd(), ext_bytes, reader)?;

        if payload_len > self.format.max_payload_length().min(MAX_PAYLOAD_LENGTH) {
            let _ = fs::unlinkat(tmp_dir_fd.as_fd(), &temp_name);
            return Err(PublishError::NotCommitted(Error::InvalidInput(
                "payload exceeds limit".into(),
            )));
        }

        let mut header = FixedHeader {
            format_minor: FORMAT_MINOR,
            extension_header_length: ext_bytes.len() as u32,
            payload_length: payload_len,
            flags: 0,
            digest_algorithm: DIGEST_ALGORITHM_SHA256,
            job_id,
            maximum_attempts,
            created_at_unix_ns: created_at,
            payload_digest,
            envelope_digest: [0; 32],
        };
        let env_dig = envelope_digest(&header, ext_bytes).ok_or_else(|| {
            PublishError::NotCommitted(Error::InvalidInput("extension length mismatch".into()))
        })?;
        header.envelope_digest = env_dig;
        let header_bytes = header
            .encode(ext_bytes)
            .map_err(|e| PublishError::NotCommitted(Error::InvalidInput(e.to_string())))?;
        fs::pwrite_all(tmp_file.as_fd(), &header_bytes, 0).map_err(PublishError::classify_write)?;
        fs::fsync(tmp_file.as_fd()).map_err(PublishError::classify_pre_pub_fsync)?;

        let temp_stat = fs::fstat(tmp_file.as_fd()).map_err(PublishError::classify_write)?;
        self.finish_named_stream_publish(
            tmp_dir_fd.as_fd(),
            dest_fd,
            &temp_name,
            dest_name,
            engine::MoveIdentity::new(temp_stat.st_dev, temp_stat.st_ino),
            env_dig,
            dirty,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_named_stream_publish(
        &self,
        tmp_dir_fd: BorrowedFd<'_>,
        dest_fd: BorrowedFd<'_>,
        temp_name: &str,
        dest_name: &str,
        identity: engine::MoveIdentity,
        envelope_digest: [u8; 32],
        dirty: Option<&mut engine::DirtySet>,
    ) -> Result<[u8; 32], PublishError> {
        if let Some(d) = dirty {
            match engine::move_witnessed_noreplace_deferred(
                tmp_dir_fd,
                temp_name,
                dest_fd,
                dest_name,
                identity,
                |_moved| Ok(()),
            ) {
                Ok(_) => {
                    d.record(tmp_dir_fd)
                        .map_err(|e| PublishError::OutcomeUnknownPublished {
                            envelope_digest,
                            error: Error::from(e),
                        })?;
                    d.record(dest_fd)
                        .map_err(|e| PublishError::OutcomeUnknownPublished {
                            envelope_digest,
                            error: Error::from(e),
                        })?;
                    Ok(envelope_digest)
                }
                Err(failure) => {
                    if failure.is_outcome_unknown() {
                        let _ = fs::unlinkat(tmp_dir_fd, temp_name);
                    }
                    Err(PublishError::from_move_failure(failure)
                        .with_published_digest(envelope_digest))
                }
            }
        } else {
            match engine::move_witnessed_noreplace_io(
                tmp_dir_fd, temp_name, dest_fd, dest_name, identity,
            ) {
                Ok(()) => Ok(envelope_digest),
                Err(failure) => {
                    if failure.is_outcome_unknown() {
                        let _ = fs::unlinkat(tmp_dir_fd, temp_name);
                    }
                    Err(PublishError::from_move_failure(failure)
                        .with_published_digest(envelope_digest))
                }
            }
        }
    }
}

/// Internal error type for publication.
pub(super) enum PublishError {
    NotCommitted(Error),
    OutcomeUnknown(Error),
    OutcomeUnknownPublished {
        envelope_digest: [u8; 32],
        error: Error,
    },
}

impl PublishError {
    pub(super) fn with_published_digest(self, envelope_digest: [u8; 32]) -> Self {
        match self {
            PublishError::OutcomeUnknown(error) => PublishError::OutcomeUnknownPublished {
                envelope_digest,
                error,
            },
            other => other,
        }
    }

    pub(super) fn classify_tmpfile(failure: engine::TmpfilePublishFailure) -> Self {
        match failure {
            engine::TmpfilePublishFailure::AlreadyExists => {
                PublishError::NotCommitted(Error::IdentityCollision)
            }
            engine::TmpfilePublishFailure::NotCommitted { phase, source } => {
                PublishError::NotCommitted(match Error::from(source) {
                    Error::IoFailure(message) => Error::IoFailure(format!(
                        "temporary-file publication failed at {phase:?}: {message}"
                    )),
                    classified => classified,
                })
            }
            engine::TmpfilePublishFailure::OutcomeUnknown { phase, source } => {
                PublishError::OutcomeUnknown(match Error::from(source) {
                    Error::IoFailure(message) => Error::IoFailure(format!(
                        "temporary-file publication failed at {phase:?}: {message}"
                    )),
                    classified => classified,
                })
            }
        }
    }

    pub(super) fn from_move_failure(failure: engine::MoveFailure) -> Self {
        match failure {
            engine::MoveFailure::AlreadyExists => {
                PublishError::NotCommitted(Error::IdentityCollision)
            }
            engine::MoveFailure::SourceMissing => PublishError::NotCommitted(Error::IoFailure(
                "temporary publication source missing".into(),
            )),
            engine::MoveFailure::NotCommitted { source, .. } => {
                PublishError::NotCommitted(Error::from(source))
            }
            engine::MoveFailure::OutcomeUnknown { source, .. } => {
                PublishError::OutcomeUnknown(Error::from(source))
            }
        }
    }

    pub(super) fn classify_write(e: io::Error) -> Self {
        PublishError::NotCommitted(Error::from(e))
    }

    /// Classify a file fsync failure that occurs BEFORE the linearizing
    /// link/rename. Per spec section 7.8, this is NotCommitted.
    pub(super) fn classify_pre_pub_fsync(e: io::Error) -> Self {
        PublishError::NotCommitted(Error::from(e))
    }
}

pub(super) fn sharded_bucket_parent(relative: &str, shard_count: u32) -> Option<&str> {
    let (bucket, shard_name) = relative.rsplit_once('/')?;
    // ready/<shard> is created and parent-synced at init.
    if bucket == "ready" {
        return None;
    }
    let shard = steadq_names::shard_from_hex(shard_name)?;
    (shard < shard_count).then_some(bucket)
}
