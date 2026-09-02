// Wall-clock watermark and authenticated wall-floor reads.
use super::*;

/// Typed wall watermark read error. Distinguishes a missing authority record
/// from corruption and I/O failures without weakening wall-sensitive work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatermarkReadError {
    NotFound,
    Truncated(String),
    Corrupt(String),
    Io(String),
}

#[derive(Debug)]
pub(crate) enum WatermarkSnapshot {
    Current(steadq_format::WatermarkRecord),
    Replaced,
}

const WATERMARK_READ_ATTEMPTS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WallFloor {
    pub(crate) unix_ns: u64,
    pub(crate) watermark_bucket: u64,
    pub(crate) watermark_sequence: u64,
}

impl WallFloor {
    pub(crate) fn unix_ns(self) -> u64 {
        self.unix_ns
    }

    #[cfg(test)]
    pub(crate) fn watermark_bucket(self) -> u64 {
        self.watermark_bucket
    }

    #[cfg(test)]
    pub(crate) fn watermark_sequence(self) -> u64 {
        self.watermark_sequence
    }
}

/// Pure helper for watermark open error classification. Returns true only for
/// NotFound, false for all other kinds. Extracted so match guard mutants are
/// killable by table tests.
pub(crate) fn watermark_open_is_not_found(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::NotFound
}

pub(crate) fn watermark_open_flags() -> i32 {
    libc::O_NOFOLLOW
        .checked_add(libc::O_CLOEXEC)
        .expect("watermark open flags must not overlap")
}

pub(crate) fn watermark_path_matches_opened(
    opened: &libc::stat,
    current: &libc::stat,
) -> Result<bool, WatermarkReadError> {
    if current.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(WatermarkReadError::Corrupt(
            "watermark is not a regular file".into(),
        ));
    }
    // A concurrent replacing rename can unlink the inode after pathname
    // resolution but before fstatat copies its attributes. Like an opened old
    // inode, that is a stale snapshot to retry rather than on-disk corruption.
    if current.st_nlink == 0 {
        return Ok(false);
    }
    if current.st_nlink != 1 {
        return Err(WatermarkReadError::Corrupt(
            "watermark is not a singly-linked regular file".into(),
        ));
    }
    Ok(identity_matches(
        current.st_dev,
        current.st_ino,
        opened.st_dev,
        opened.st_ino,
    ))
}

/// Pure helper for watermark advance decision. Returns true when observed
/// bucket is strictly greater than stored bucket. Extracted so <= vs > mutants
/// are killable.
pub(crate) fn watermark_should_advance(observed_bucket: u64, stored_bucket: u64) -> bool {
    observed_bucket > stored_bucket
}

impl Queue {
    /// Compute the effective wall floor: max(CLOCK_REALTIME, stored watermark bucket * width)
    /// Wall floor for mutating operations. Returns Err and poisons on
    /// non-transient failure so callers abort before computing destination paths.
    pub(crate) fn wall_floor_for_mutation(&mut self) -> Result<WallFloor, Error> {
        self.wall_floor_for_mutation_with_attempts(WATERMARK_READ_ATTEMPTS)
    }

    pub(crate) fn wall_floor_for_mutation_with_attempts(
        &mut self,
        watermark_read_attempts: usize,
    ) -> Result<WallFloor, Error> {
        // A process-local cache cannot establish the shared durable floor: another
        // handle may advance the watermark while realtime rolls back into this
        // handle's cached bucket. Authenticate shared state before using the cache.
        if let Some(cached) = self.cached_wall_floor {
            let authenticated =
                match self.authenticated_wall_floor_with_attempts(watermark_read_attempts) {
                    Ok(floor) => floor,
                    Err(error @ (Error::MaintenanceBusy | Error::ResourceExhausted)) => {
                        return Err(error)
                    }
                    Err(error) => {
                        self.poison(PoisonReason::WatermarkAuthorityLost);
                        return Err(error);
                    }
                };
            let observed_bucket = steadq_math::bucket_number(
                authenticated.unix_ns(),
                self.format.delayed_bucket_width_ns(),
            )
            .ok_or(Error::StateExhausted)?;
            if observed_bucket == authenticated.watermark_bucket
                && cached.watermark_bucket == authenticated.watermark_bucket
                && cached.watermark_sequence == authenticated.watermark_sequence
            {
                let floor = WallFloor {
                    unix_ns: cached.unix_ns.max(authenticated.unix_ns),
                    ..authenticated
                };
                self.cached_wall_floor = Some(floor);
                return Ok(floor);
            }
        }

        // Slow path: acquire the watermark lock, read, and potentially advance.
        match self.stabilized_wall_floor() {
            Ok(floor) => {
                self.cached_wall_floor = Some(floor);
                Ok(floor)
            }
            Err(e @ (Error::MaintenanceBusy | Error::ResourceExhausted)) => Err(e),
            Err(e) => {
                self.poison(PoisonReason::WatermarkAuthorityLost);
                Err(e)
            }
        }
    }

    /// Fallible version of effective_wall_floor_ns.
    pub fn effective_wall_floor_ns_checked(&self) -> Result<u64, Error> {
        self.authenticated_wall_floor().map(WallFloor::unix_ns)
    }

    pub(crate) fn authenticated_wall_floor(&self) -> Result<WallFloor, Error> {
        self.authenticated_wall_floor_with_attempts(WATERMARK_READ_ATTEMPTS)
    }

    pub(crate) fn authenticated_wall_floor_with_attempts(
        &self,
        watermark_read_attempts: usize,
    ) -> Result<WallFloor, Error> {
        let watermark = match self.try_read_wall_watermark(watermark_read_attempts) {
            Ok(Some(watermark)) => watermark,
            Ok(None) => return Err(Error::MaintenanceBusy),
            Err(WatermarkReadError::NotFound) => {
                return Err(Error::QueueCorrupt("wall watermark missing".into()));
            }
            Err(WatermarkReadError::Truncated(msg)) => {
                return Err(Error::QueueCorrupt(format!("watermark truncated: {msg}")));
            }
            Err(WatermarkReadError::Corrupt(msg)) => {
                return Err(Error::QueueCorrupt(format!("watermark corrupt: {msg}")));
            }
            Err(WatermarkReadError::Io(msg)) => return Err(Error::IoFailure(msg)),
        };
        let clock = steadq_fs_linux::clock_realtime_ns()
            .map_err(|e| Error::IoFailure(format!("CLOCK_REALTIME: {e}")))?;
        let unix_ns = steadq_math::effective_wall_floor(
            clock,
            watermark.highest_observed_bucket,
            self.format.delayed_bucket_width_ns(),
        )
        .ok_or_else(|| Error::QueueCorrupt("watermark computation overflow".into()))?;
        Ok(WallFloor {
            unix_ns,
            watermark_bucket: watermark.highest_observed_bucket,
            watermark_sequence: watermark.sequence,
        })
    }

    pub(crate) fn stabilized_wall_floor(&self) -> Result<WallFloor, Error> {
        self.with_wall_watermark_write_lock(|control_fd| {
            let observed = self.authenticated_wall_floor()?;
            let observed_bucket = steadq_math::bucket_number(
                observed.unix_ns(),
                self.format.delayed_bucket_width_ns(),
            )
            .ok_or(Error::StateExhausted)?;
            if !watermark_should_advance(observed_bucket, observed.watermark_bucket) {
                return Ok(observed);
            }

            self.advance_wall_watermark_locked(observed, control_fd)
        })
    }

    pub(crate) fn with_wall_watermark_write_lock<T>(
        &self,
        action: impl FnOnce(BorrowedFd<'_>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let control_fd =
            fs::open_directory(self.root_fd.as_fd(), "control").map_err(Error::from)?;
        let lock_fd = fs::openat(
            control_fd.as_fd(),
            "wall-watermark.lock",
            libc::O_RDWR,
            0o600,
        )
        .map_err(Error::from)?;
        let locked = fs::try_ofd_write_lock(lock_fd.as_fd()).map_err(Error::from)?;
        if !locked {
            return Err(Error::MaintenanceBusy);
        }

        action(control_fd.as_fd())
    }

    /// Read the wall watermark record from control/wall-watermark.
    /// Returns Ok on success, Err(NotFound) when no watermark has been written yet,
    /// Err(Corrupt/Truncated) on digest or size mismatch, Err(Io) on I/O failure.
    pub(crate) fn read_wall_watermark(
        &self,
    ) -> Result<steadq_format::WatermarkRecord, WatermarkReadError> {
        match self.try_read_wall_watermark(WATERMARK_READ_ATTEMPTS)? {
            Some(watermark) => Ok(watermark),
            None => Err(WatermarkReadError::Io(format!(
                "wall watermark changed during {WATERMARK_READ_ATTEMPTS} consecutive reads"
            ))),
        }
    }

    /// Optimistically authenticate the shared watermark without taking its lock.
    /// `Ok(None)` is transient replacement contention, not an I/O failure.
    pub(crate) fn try_read_wall_watermark(
        &self,
        attempts: usize,
    ) -> Result<Option<steadq_format::WatermarkRecord>, WatermarkReadError> {
        let control_fd = fs::open_directory(self.root_fd.as_fd(), "control")
            .map_err(|e| WatermarkReadError::Io(e.to_string()))?;

        for _ in 0..attempts {
            let cached = {
                let cached = self.cached_watermark_fd.borrow();
                cached
                    .as_ref()
                    .map(|data| Self::read_opened_wall_watermark(control_fd.as_fd(), data.as_fd()))
            };
            if let Some(snapshot) = cached {
                match snapshot? {
                    WatermarkSnapshot::Current(watermark) => return Ok(Some(watermark)),
                    WatermarkSnapshot::Replaced => {
                        self.cached_watermark_fd.borrow_mut().take();
                    }
                }
            }

            let data = match fs::openat(
                control_fd.as_fd(),
                "wall-watermark",
                watermark_open_flags(),
                0,
            ) {
                Ok(fd) => fd,
                Err(e) => {
                    if watermark_open_is_not_found(&e) {
                        return Err(WatermarkReadError::NotFound);
                    }
                    return Err(WatermarkReadError::Io(e.to_string()));
                }
            };

            match Self::read_opened_wall_watermark(control_fd.as_fd(), data.as_fd())? {
                WatermarkSnapshot::Current(watermark) => {
                    self.cached_watermark_fd.borrow_mut().replace(data);
                    return Ok(Some(watermark));
                }
                WatermarkSnapshot::Replaced => continue,
            }
        }

        Ok(None)
    }

    pub(crate) fn read_opened_wall_watermark(
        control_fd: BorrowedFd<'_>,
        data_fd: BorrowedFd<'_>,
    ) -> Result<WatermarkSnapshot, WatermarkReadError> {
        let stat = fs::fstat(data_fd).map_err(|e| WatermarkReadError::Io(e.to_string()))?;
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err(WatermarkReadError::Corrupt(
                "watermark is not a regular file".into(),
            ));
        }
        if stat.st_nlink == 0 {
            return Ok(WatermarkSnapshot::Replaced);
        }
        if stat.st_nlink != 1 {
            return Err(WatermarkReadError::Corrupt(
                "watermark is not a singly-linked regular file".into(),
            ));
        }
        if stat.st_size < steadq_format::WATERMARK_SIZE as i64 {
            return Err(WatermarkReadError::Truncated(format!(
                "expected {} bytes, found {}",
                steadq_format::WATERMARK_SIZE,
                stat.st_size
            )));
        }
        if stat.st_size != steadq_format::WATERMARK_SIZE as i64 {
            return Err(WatermarkReadError::Corrupt(format!(
                "expected {} bytes, found {}",
                steadq_format::WATERMARK_SIZE,
                stat.st_size
            )));
        }
        let mut buf = [0u8; steadq_format::WATERMARK_SIZE];
        if let Err(error) = fs::pread_exact(data_fd, &mut buf, 0) {
            return if error.kind() == io::ErrorKind::UnexpectedEof {
                Err(WatermarkReadError::Truncated(error.to_string()))
            } else {
                Err(WatermarkReadError::Io(error.to_string()))
            };
        }
        let watermark = steadq_format::WatermarkRecord::decode(&buf)
            .map_err(|e| WatermarkReadError::Corrupt(e.to_string()))?;

        let current = fs::fstatat(control_fd, "wall-watermark").map_err(|error| {
            if watermark_open_is_not_found(&error) {
                WatermarkReadError::NotFound
            } else {
                WatermarkReadError::Io(error.to_string())
            }
        })?;
        if !watermark_path_matches_opened(&stat, &current)? {
            return Ok(WatermarkSnapshot::Replaced);
        }

        Ok(WatermarkSnapshot::Current(watermark))
    }

    /// Requires the exclusive wall-watermark lock to remain held until return.
    pub(crate) fn advance_wall_watermark_locked(
        &self,
        observed: WallFloor,
        control_fd: BorrowedFd<'_>,
    ) -> Result<WallFloor, Error> {
        let observed_bucket =
            steadq_math::bucket_number(observed.unix_ns(), self.format.delayed_bucket_width_ns())
                .ok_or(Error::StateExhausted)?;

        // Re-read current watermark under lock
        let current = self.read_wall_watermark();
        let (new_bucket, new_seq) = match current {
            Ok(wm) => {
                if !watermark_should_advance(observed_bucket, wm.highest_observed_bucket) {
                    let durable_ns = wm
                        .highest_observed_bucket
                        .checked_mul(self.format.delayed_bucket_width_ns())
                        .ok_or(Error::StateExhausted)?;
                    return Ok(WallFloor {
                        unix_ns: observed.unix_ns().max(durable_ns),
                        watermark_bucket: wm.highest_observed_bucket,
                        watermark_sequence: wm.sequence,
                    });
                }
                let new_seq = wm.sequence.checked_add(1).ok_or(Error::StateExhausted)?;
                (observed_bucket, new_seq)
            }
            Err(WatermarkReadError::NotFound) => {
                return Err(Error::QueueCorrupt("wall watermark missing".into()));
            }
            Err(WatermarkReadError::Truncated(msg)) => {
                return Err(Error::QueueCorrupt(format!("watermark truncated: {msg}")))
            }
            Err(WatermarkReadError::Corrupt(msg)) => {
                return Err(Error::QueueCorrupt(format!("watermark corrupt: {msg}")))
            }
            Err(WatermarkReadError::Io(msg)) => return Err(Error::IoFailure(msg)),
        };

        let new_wm = steadq_format::WatermarkRecord {
            highest_observed_bucket: new_bucket,
            sequence: new_seq,
        };
        let wm_bytes = new_wm.encode();

        // Write via unique temp, then atomic rename, then sync
        let tmp_name = format!(
            ".wm.adv.{}",
            steadq_names::hex_encode(&fs::random_128bit().map_err(Error::from)?)
        );
        let tmp_fd = fs::create_exclusive(control_fd, &tmp_name, 0o600).map_err(Error::from)?;
        let written = fs::write_all(tmp_fd.as_fd(), &wm_bytes)
            .and_then(|()| fs::fsync(tmp_fd.as_fd()))
            .and_then(|()| fs::renameat(control_fd, &tmp_name, control_fd, "wall-watermark"));
        if let Err(error) = written {
            // The temp never became the watermark, so drop it; a retry after
            // ENOSPC must not leave one orphan per attempt in control/.
            let _ = fs::unlinkat(control_fd, &tmp_name);
            return Err(Error::from(error));
        }
        // Past the rename the outcome is indeterminate, so no errno may
        // downgrade it to a retryable classification.
        fs::fsync_dir_fd(control_fd)
            .map_err(|e| Error::IoFailure(format!("watermark directory fsync: {e}")))?;

        Ok(WallFloor {
            unix_ns: observed.unix_ns(),
            watermark_bucket: new_bucket,
            watermark_sequence: new_seq,
        })
    }
}
