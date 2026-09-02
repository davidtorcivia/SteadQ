// Outcome-unknown resolution: observe, classify, stabilize.
use super::*;

/// Internal helper enum for resolver object authentication.
pub(crate) enum ResolveObj {
    Absent,
    Match(ResolvedObject),
    Conflict,
    Error(Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResolverObjectVerifier {
    Job,
    Receipt,
}
pub(crate) struct ResolvedObject {
    directory_fd: OwnedFd,
    directory_device: u64,
    directory_inode: u64,
    file_fd: OwnedFd,
    device: u64,
    inode: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResolverObjectOpenFailure {
    Absent,
    Conflict,
    Io,
}
pub(crate) fn resolver_error_is_not_found(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::ENOENT)
}

pub(crate) fn resolver_object_verifier(
    object_kind: ObjectKind,
    state_directory: &str,
) -> Option<ResolverObjectVerifier> {
    match object_kind {
        ObjectKind::FullJob
            if matches!(state_directory, "ready" | "leased" | "delayed" | "dead") =>
        {
            Some(ResolverObjectVerifier::Job)
        }
        ObjectKind::FullReceipt | ObjectKind::CompactReceipt if state_directory == "receipts" => {
            Some(ResolverObjectVerifier::Receipt)
        }
        ObjectKind::FullJob
        | ObjectKind::FullReceipt
        | ObjectKind::CompactReceipt
        | ObjectKind::RawObject
        | ObjectKind::WatermarkRecord => None,
    }
}
pub(crate) fn resolved_identity_matches(
    mode: libc::mode_t,
    device: u64,
    inode: u64,
    expected_device: u64,
    expected_inode: u64,
) -> bool {
    mode & libc::S_IFMT == libc::S_IFREG
        && identity_matches(device, inode, expected_device, expected_inode)
}
pub(crate) struct ResolvePath<'a> {
    pub(crate) directory: fs::ValidatedRelativePath<'a>,
    pub(crate) name: &'a str,
    pub(crate) parts: Vec<&'a str>,
}

pub(crate) fn classify_resolver_object_open_failure(
    error: &io::Error,
) -> ResolverObjectOpenFailure {
    match error.raw_os_error() {
        Some(libc::ENOENT) => ResolverObjectOpenFailure::Absent,
        Some(libc::ELOOP) => ResolverObjectOpenFailure::Conflict,
        _ => ResolverObjectOpenFailure::Io,
    }
}

impl<'a> ResolvePath<'a> {
    pub(crate) fn new(path: &'a str) -> Result<Self, Error> {
        let relative = fs::ValidatedRelativePath::new(path)
            .map_err(|error| Error::InvalidInput(error.to_string()))?;
        let (directory, name) = relative
            .as_str()
            .rsplit_once('/')
            .ok_or_else(|| Error::InvalidInput("ticket path has no parent directory".into()))?;
        let directory = fs::ValidatedRelativePath::new(directory)
            .map_err(|error| Error::InvalidInput(error.to_string()))?;
        Ok(Self {
            directory,
            name,
            parts: relative.components().collect(),
        })
    }
}

impl Queue {
    pub fn resolve(&self, ticket: &TransitionTicket, stabilize: bool) -> ResolutionOutcome {
        let (source_relative_path, destination_relative_path) =
            match self.transition_ticket_paths(ticket) {
                Ok(paths) => paths,
                Err(error) => return ResolutionOutcome::ResolutionFailed(error),
            };
        let source_path = match ResolvePath::new(&source_relative_path) {
            Ok(path) => path,
            Err(error) => return ResolutionOutcome::ResolutionFailed(error),
        };
        let destination_path = match ResolvePath::new(&destination_relative_path) {
            Ok(path) => path,
            Err(error) => return ResolutionOutcome::ResolutionFailed(error),
        };
        let source_common = ticket.source_common();
        let destination_common = match ticket.destination_common() {
            Ok(common) => common,
            Err(error) => return ResolutionOutcome::ResolutionFailed(error),
        };
        let (source_object_kind, destination_object_kind) = ticket.object_kinds();

        let src_result =
            self.resolve_check_object(&source_path, ticket, &source_common, source_object_kind);
        let dest_result = self.resolve_check_object(
            &destination_path,
            ticket,
            &destination_common,
            destination_object_kind,
        );

        match (src_result, dest_result) {
            // Source exists but destination doesn't
            (ResolveObj::Match(source), ResolveObj::Absent) => {
                if stabilize {
                    match self.stabilize_object(&source_path, &source) {
                        Ok(true) => ResolutionOutcome::SourceStabilized,
                        Ok(false) => ResolutionOutcome::ConflictingObject,
                        Err(error) => ResolutionOutcome::ResolutionFailed(error),
                    }
                } else {
                    ResolutionOutcome::SourceObserved
                }
            }
            // Destination exists but source doesn't
            (ResolveObj::Absent, ResolveObj::Match(destination)) => {
                if stabilize {
                    match self.stabilize_object(&destination_path, &destination) {
                        Ok(true) => ResolutionOutcome::DestinationStabilized,
                        Ok(false) => ResolutionOutcome::ConflictingObject,
                        Err(error) => ResolutionOutcome::ResolutionFailed(error),
                    }
                } else {
                    ResolutionOutcome::DestinationObserved
                }
            }
            (ResolveObj::Absent, ResolveObj::Absent) => ResolutionOutcome::NeitherObserved,
            (ResolveObj::Match(_), ResolveObj::Match(_)) => ResolutionOutcome::BothObserved,
            // Any conflict
            (ResolveObj::Conflict, _) | (_, ResolveObj::Conflict) => {
                ResolutionOutcome::ConflictingObject
            }
            // I/O errors
            (ResolveObj::Error(e), _) | (_, ResolveObj::Error(e)) => {
                ResolutionOutcome::ResolutionFailed(e)
            }
        }
    }

    pub fn transition_ticket_paths(
        &self,
        ticket: &TransitionTicket,
    ) -> Result<(String, String), Error> {
        ticket.validate_for_queue(self.format.queue_id())?;
        let source_common = ticket.source_common();
        let destination_common = ticket.destination_common()?;
        let layout = self.layout();
        let source = match ticket.source() {
            TicketSource::Ready {} => layout.ready(&source_common),
            TicketSource::Leased {
                boot_id,
                boottime_deadline_ns,
                wall_deadline_ns,
            } => layout.leased_for_boot(
                &source_common,
                boot_id,
                *boottime_deadline_ns,
                *wall_deadline_ns,
                &ticket.lease_token(),
            )?,
        };
        let destination = match ticket.destination() {
            TicketDestination::Ready {} => layout.ready(&destination_common),
            TicketDestination::Leased {
                boot_id,
                boottime_deadline_ns,
                wall_deadline_ns,
            } => layout.leased_for_boot(
                &destination_common,
                boot_id,
                *boottime_deadline_ns,
                *wall_deadline_ns,
                &ticket.lease_token(),
            )?,
            TicketDestination::Delayed { not_before_ns } => {
                layout.delayed(&destination_common, *not_before_ns)?
            }
            TicketDestination::Receipt { terminal_bucket } => layout.receipt_in_bucket(
                &destination_common,
                &ticket.lease_token(),
                *terminal_bucket,
            ),
            TicketDestination::Dead {
                terminal_bucket,
                reason,
            } => layout.dead_in_bucket(&destination_common, *reason, *terminal_bucket),
        };
        Ok((source.relative_path(), destination.relative_path()))
    }

    pub(crate) fn resolve_check_object(
        &self,
        path: &ResolvePath<'_>,
        ticket: &TransitionTicket,
        expected_common: &CommonFields,
        object_kind: ObjectKind,
    ) -> ResolveObj {
        let parts = &path.parts;
        let name = path.name;
        let verifier = match resolver_object_verifier(object_kind, parts[0]) {
            Some(verifier) => verifier,
            None => return ResolveObj::Conflict,
        };

        let dir_fd = match fs::open_directory_beneath(self.root_fd.as_fd(), path.directory) {
            Ok(fd) => fd,
            Err(error) => match classify_presence_failure(&error) {
                PresenceFailure::Absent => return ResolveObj::Absent,
                PresenceFailure::Io => {
                    return ResolveObj::Error(Error::from(error));
                }
            },
        };
        let directory_stat = match fs::fstat(dir_fd.as_fd()) {
            Ok(stat) => stat,
            Err(error) => return ResolveObj::Error(Error::from(error)),
        };

        let file_fd = match fs::openat(dir_fd.as_fd(), name, resolver_file_open_flags(), 0) {
            Ok(fd) => fd,
            Err(error) => match classify_resolver_object_open_failure(&error) {
                ResolverObjectOpenFailure::Absent => return ResolveObj::Absent,
                ResolverObjectOpenFailure::Conflict => return ResolveObj::Conflict,
                ResolverObjectOpenFailure::Io => {
                    return ResolveObj::Error(Error::from(error));
                }
            },
        };
        let stat = match fs::fstat(file_fd.as_fd()) {
            Ok(stat) => stat,
            Err(error) => return ResolveObj::Error(Error::from(error)),
        };

        if !is_singly_linked_regular(stat.st_mode, stat.st_nlink) {
            return ResolveObj::Conflict;
        }

        // Read the 128-byte header buffer.
        let mut header_buf = [0u8; 128];
        if let Err(error) = fs::pread_exact(file_fd.as_fd(), &mut header_buf, 0) {
            return if error.kind() == io::ErrorKind::UnexpectedEof {
                ResolveObj::Conflict
            } else {
                ResolveObj::Error(Error::from(error))
            };
        }

        let state = parts[0];

        if verifier == ResolverObjectVerifier::Receipt {
            if parts.len() != 4 {
                return ResolveObj::Conflict;
            }
            let expected = verified::ExpectedReceipt {
                common: expected_common.clone(),
                token: ticket.lease_token(),
                envelope_digest: ticket.envelope_digest(),
                payload_length: ticket.payload_length(),
            };
            match verified::verify_receipt_on_fd(
                file_fd.as_fd(),
                verified::ReceiptContext {
                    queue_id: self.format.queue_id(),
                    shard_count: self.format.shard_count(),
                    terminal_bucket_width_ns: self.format.terminal_bucket_width_ns(),
                    max_payload_length: self.format.max_payload_length(),
                    bucket: parts[1],
                    shard: parts[2],
                    filename: name,
                },
                Some(&expected),
            ) {
                Ok(_) => {
                    return ResolveObj::Match(ResolvedObject {
                        directory_fd: dir_fd,
                        directory_device: directory_stat.st_dev as u64,
                        directory_inode: directory_stat.st_ino as u64,
                        file_fd,
                        device: stat.st_dev as u64,
                        inode: stat.st_ino as u64,
                    });
                }
                Err(verified::VerificationError::Io(error)) => {
                    return ResolveObj::Error(Error::IoFailure(error));
                }
                Err(
                    verified::VerificationError::Corrupt(_)
                    | verified::VerificationError::PayloadCorrupt,
                ) => return ResolveObj::Conflict,
            }
        }

        let verified = match verified::verify_job_on_fd(file_fd.as_fd()) {
            Ok(verified) => verified,
            Err(verified::VerificationError::Io(error)) => {
                return ResolveObj::Error(Error::IoFailure(error));
            }
            Err(
                verified::VerificationError::Corrupt(_)
                | verified::VerificationError::PayloadCorrupt,
            ) => return ResolveObj::Conflict,
        };
        let header = verified.header();

        // Verify header job_id matches the ticket.
        if header.job_id != ticket.job_id() {
            return ResolveObj::Conflict;
        }
        if header.maximum_attempts != expected_common.maximum_attempts {
            return ResolveObj::Conflict;
        }

        if header.envelope_digest != ticket.envelope_digest() {
            return ResolveObj::Conflict;
        }
        if header.payload_length != ticket.payload_length() {
            return ResolveObj::Conflict;
        }

        // Parse the filename using the state-appropriate parser and
        // verify identity fields against the ticket. The state is derived from
        // the path prefix, not trusted from the ticket.
        match state {
            "ready" => {
                if parts.len() != 3 {
                    return ResolveObj::Conflict;
                }
                let shard_hex = parts[1];
                if let Ok(p) = steadq_names::parse_ready(name) {
                    if &p.common != expected_common {
                        return ResolveObj::Conflict;
                    }
                    if !p.authenticate_tag(self.format.queue_id(), shard_hex) {
                        return ResolveObj::Conflict;
                    }
                    if !self.verify_shard_placement(shard_hex, &ticket.job_id()) {
                        return ResolveObj::Conflict;
                    }
                } else if let Ok(p) = steadq_names::parse_leased(name) {
                    if &p.common != expected_common {
                        return ResolveObj::Conflict;
                    }
                    if p.token != ticket.lease_token() {
                        return ResolveObj::Conflict;
                    }
                    let boot = steadq_names::format_boot_id(&p.boot_id);
                    let Some(bucket) = steadq_math::lease_bucket(
                        p.boottime_deadline_ns,
                        self.format.lease_bucket_width_ns(),
                    ) else {
                        return ResolveObj::Conflict;
                    };
                    let bucket_hex = steadq_names::bucket_hex(bucket);
                    if !p.authenticate_tag(self.format.queue_id(), &boot, &bucket_hex, shard_hex) {
                        return ResolveObj::Conflict;
                    }
                    if !self.verify_shard_placement(shard_hex, &ticket.job_id()) {
                        return ResolveObj::Conflict;
                    }
                } else {
                    return ResolveObj::Conflict;
                }
            }
            "leased" => {
                // leased/<boot>/<bucket>/<shard>/<file> = 5 parts
                if parts.len() != 5 {
                    return ResolveObj::Conflict;
                }
                let p = match steadq_names::parse_leased(name) {
                    Ok(p) => p,
                    Err(_) => return ResolveObj::Conflict,
                };
                if &p.common != expected_common {
                    return ResolveObj::Conflict;
                }
                if p.token != ticket.lease_token() {
                    return ResolveObj::Conflict;
                }
                let boot = parts[1];
                let bucket = parts[2];
                let shard_hex = parts[3];
                if !p.authenticate_tag(self.format.queue_id(), boot, bucket, shard_hex) {
                    return ResolveObj::Conflict;
                }
                if !self.verify_shard_placement(shard_hex, &ticket.job_id()) {
                    return ResolveObj::Conflict;
                }
            }
            "delayed" => {
                // delayed/<bucket>/<shard>/<file> = 4 parts
                if parts.len() != 4 {
                    return ResolveObj::Conflict;
                }
                let p = match steadq_names::parse_delayed(name) {
                    Ok(p) => p,
                    Err(_) => return ResolveObj::Conflict,
                };
                if &p.common != expected_common {
                    return ResolveObj::Conflict;
                }
                let bucket = parts[1];
                let shard_hex = parts[2];
                if !p.authenticate_tag(self.format.queue_id(), bucket, shard_hex) {
                    return ResolveObj::Conflict;
                }
                if !self.verify_shard_placement(shard_hex, &ticket.job_id()) {
                    return ResolveObj::Conflict;
                }
            }
            "dead" => {
                // dead/<bucket>/<shard>/<file> = 4 parts
                if parts.len() != 4 {
                    return ResolveObj::Conflict;
                }
                let p = match steadq_names::parse_dead(name) {
                    Ok(p) => p,
                    Err(_) => return ResolveObj::Conflict,
                };
                if &p.common != expected_common {
                    return ResolveObj::Conflict;
                }
                let bucket = parts[1];
                let shard_hex = parts[2];
                if !p.authenticate_tag(self.format.queue_id(), bucket, shard_hex) {
                    return ResolveObj::Conflict;
                }
                if !self.verify_shard_placement(shard_hex, &ticket.job_id()) {
                    return ResolveObj::Conflict;
                }
            }
            _ => return ResolveObj::Conflict,
        }

        ResolveObj::Match(ResolvedObject {
            directory_fd: dir_fd,
            directory_device: directory_stat.st_dev as u64,
            directory_inode: directory_stat.st_ino as u64,
            file_fd,
            device: stat.st_dev as u64,
            inode: stat.st_ino as u64,
        })
    }

    pub(crate) fn stabilize_object(
        &self,
        path: &ResolvePath<'_>,
        object: &ResolvedObject,
    ) -> Result<bool, Error> {
        fs::fsync(object.file_fd.as_fd()).map_err(Error::from)?;
        fs::fsync_dir_fd(object.directory_fd.as_fd()).map_err(Error::from)?;
        let current_directory =
            match fs::open_directory_beneath(self.root_fd.as_fd(), path.directory) {
                Ok(directory) => directory,
                Err(error) => {
                    if resolver_error_is_not_found(&error) {
                        return Ok(false);
                    }
                    return Err(Error::from(error));
                }
            };
        let current_directory_stat = fs::fstat(current_directory.as_fd()).map_err(Error::from)?;
        if !identity_matches(
            current_directory_stat.st_dev as u64,
            current_directory_stat.st_ino as u64,
            object.directory_device,
            object.directory_inode,
        ) {
            return Ok(false);
        }
        let current = match fs::fstatat(current_directory.as_fd(), path.name) {
            Ok(stat) => stat,
            Err(error) => {
                if resolver_error_is_not_found(&error) {
                    return Ok(false);
                }
                return Err(Error::from(error));
            }
        };
        Ok(resolved_identity_matches(
            current.st_mode,
            current.st_dev as u64,
            current.st_ino as u64,
            object.device,
            object.inode,
        ))
    }
}
