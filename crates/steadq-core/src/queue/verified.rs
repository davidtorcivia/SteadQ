// Central object verifier: single source of truth for envelope and payload validation.
//
// Callers obtain a VerifiedJob only after the full chain has been checked:
// header decode, extension length bound, envelope digest, size, and payload digest.
// This prevents delivery of corrupt objects via lease or read paths.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use sha2::Digest;

use steadq_format::{CompactReceipt, FixedHeader, COMPACT_RECEIPT_SIZE, RECEIPT_MAGIC};
use steadq_fs_linux as fs;
use steadq_names::{CommonFields, ReceiptName};

use crate::errors::Error;

/// Convert a libc stat st_size (i64) to u64, rejecting negative sizes.
fn file_size(stat: &libc::stat) -> Result<u64, VerificationError> {
    if stat.st_size < 0 {
        return Err(VerificationError::Corrupt(format!(
            "negative file size: {}",
            stat.st_size
        )));
    }
    Ok(stat.st_size as u64)
}

/// Checked total size: 128 + ext_len + payload_length without overflow.
pub(crate) fn checked_total_size(
    ext_len: usize,
    payload_length: u64,
) -> Result<u64, VerificationError> {
    let header_ext = 128u64
        .checked_add(ext_len as u64)
        .ok_or_else(|| VerificationError::Corrupt("size overflow".into()))?;
    header_ext
        .checked_add(payload_length)
        .ok_or_else(|| VerificationError::Corrupt("size overflow".into()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    Io(String),
    Corrupt(String),
    PayloadCorrupt,
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(s) => write!(f, "I/O: {s}"),
            Self::Corrupt(s) => write!(f, "corrupt: {s}"),
            Self::PayloadCorrupt => write!(f, "payload corrupt"),
        }
    }
}

impl std::error::Error for VerificationError {}

impl From<VerificationError> for Error {
    fn from(e: VerificationError) -> Self {
        match e {
            VerificationError::Io(s) => Error::IoFailure(s),
            VerificationError::Corrupt(s) => Error::QueueCorrupt(s),
            VerificationError::PayloadCorrupt => Error::PayloadCorrupt,
        }
    }
}

/// A job envelope that has passed full verification on its held fd.
#[derive(Debug)]
pub struct VerifiedJob {
    fd: OwnedFd,
    header: FixedHeader,
    extension: Vec<u8>,
    device: u64,
    inode: u64,
    size: u64,
}

impl VerifiedJob {
    pub fn header(&self) -> &FixedHeader {
        &self.header
    }

    pub fn extension(&self) -> &[u8] {
        &self.extension
    }

    pub fn device(&self) -> u64 {
        self.device
    }

    pub fn inode(&self) -> u64 {
        self.inode
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    /// Borrow the verified file descriptor for direct reads.
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    pub fn identity_matches(&self, stat: &libc::stat) -> bool {
        stat.st_dev == self.device && stat.st_ino == self.inode
    }
}

/// Queue and path context required to authenticate a receipt.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ReceiptContext<'a> {
    pub(crate) queue_id: &'a [u8; 16],
    pub(crate) shard_count: u32,
    pub(crate) terminal_bucket_width_ns: u64,
    pub(crate) max_payload_length: u64,
    pub(crate) bucket: &'a str,
    pub(crate) shard: &'a str,
    pub(crate) filename: &'a str,
}

/// Optional operation identity that a receipt must represent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExpectedReceipt {
    pub(crate) common: CommonFields,
    pub(crate) token: [u8; 16],
    pub(crate) envelope_digest: [u8; 32],
    pub(crate) payload_length: u64,
}

/// A receipt authenticated against its queue path and wire contents.
#[derive(Debug)]
pub(crate) enum VerifiedReceiptKind {
    Full(VerifiedJob),
    Compact,
}

#[derive(Debug)]
pub(crate) struct VerifiedReceipt {
    pub(crate) name: ReceiptName,
    pub(crate) bucket_number: u64,
    pub(crate) kind: VerifiedReceiptKind,
    pub(crate) device: u64,
    pub(crate) inode: u64,
}

pub(crate) fn receipt_read_open_flags() -> i32 {
    libc::O_RDONLY
        .checked_add(libc::O_CLOEXEC)
        .and_then(|flags| flags.checked_add(libc::O_NOFOLLOW))
        .expect("receipt read flags are disjoint")
}

pub(crate) fn receipt_write_open_flags() -> i32 {
    libc::O_RDWR
        .checked_add(libc::O_CLOEXEC)
        .and_then(|flags| flags.checked_add(libc::O_NOFOLLOW))
        .expect("receipt write flags are disjoint")
}

pub(crate) fn receipt_path_identity_matches(
    stat: &libc::stat,
    expected_device: u64,
    expected_inode: u64,
) -> bool {
    stat.st_dev == expected_device && stat.st_ino == expected_inode
}

fn receipt_attempt_is_valid(attempt: u32, maximum_attempts: u32) -> bool {
    if maximum_attempts == 0 {
        return false;
    }
    if attempt == 0 {
        return false;
    }
    attempt <= maximum_attempts
}

fn is_compact_receipt(file_size: u64, record: &[u8; COMPACT_RECEIPT_SIZE]) -> bool {
    if file_size != COMPACT_RECEIPT_SIZE as u64 {
        return false;
    }
    &record[0..RECEIPT_MAGIC.len()] == RECEIPT_MAGIC
}

fn payload_length_is_allowed(payload_length: u64, maximum: u64) -> bool {
    payload_length <= maximum
}

fn compact_path_fields_match(
    compact: &CompactReceipt,
    name: &ReceiptName,
    bucket_start: u64,
) -> bool {
    compact.job_id == name.common.job_id
        && compact.lease_token == name.token
        && compact.final_attempt == name.common.attempt
        && compact.receipt_bucket_start_unix_ns == bucket_start
}

fn expected_name_matches(name: &ReceiptName, expected: &ExpectedReceipt) -> bool {
    name.common == expected.common && name.token == expected.token
}

fn compact_evidence_matches(compact: &CompactReceipt, expected: &ExpectedReceipt) -> bool {
    compact.envelope_digest == expected.envelope_digest
        && compact.original_payload_length == expected.payload_length
}

fn full_path_fields_match(header: &FixedHeader, name: &ReceiptName) -> bool {
    header.job_id == name.common.job_id && header.maximum_attempts == name.common.maximum_attempts
}

fn full_evidence_matches(header: &FixedHeader, expected: &ExpectedReceipt) -> bool {
    header.envelope_digest == expected.envelope_digest
        && header.payload_length == expected.payload_length
}

/// Authenticate a full or compact receipt using one strict policy.
///
/// Full receipts always receive payload verification. This is intentionally
/// stronger than envelope-only inspection because compaction and duplicate
/// acknowledgment must never erase or trust corrupt payload evidence.
pub(crate) fn verify_receipt_on_fd(
    fd: BorrowedFd<'_>,
    context: ReceiptContext<'_>,
    expected: Option<&ExpectedReceipt>,
) -> Result<VerifiedReceipt, VerificationError> {
    let stat = fs::fstat(fd).map_err(|error| VerificationError::Io(error.to_string()))?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(VerificationError::Corrupt(
            "receipt is not a regular file".into(),
        ));
    }
    if stat.st_nlink != 1 {
        return Err(VerificationError::Corrupt(format!(
            "receipt link count is {}, expected 1",
            stat.st_nlink
        )));
    }
    let file_size = u64::try_from(stat.st_size)
        .map_err(|_| VerificationError::Corrupt("receipt has a negative file size".into()))?;

    let name = steadq_names::parse_receipt(context.filename)
        .map_err(|error| VerificationError::Corrupt(format!("receipt filename: {error}")))?;
    if !receipt_attempt_is_valid(name.common.attempt, name.common.maximum_attempts) {
        return Err(VerificationError::Corrupt(
            "receipt attempt fields are invalid".into(),
        ));
    }
    if !name.authenticate_tag(context.queue_id, context.bucket, context.shard) {
        return Err(VerificationError::Corrupt(
            "receipt name tag mismatch".into(),
        ));
    }
    let path_shard = steadq_names::shard_from_hex(context.shard)
        .ok_or_else(|| VerificationError::Corrupt("receipt shard is invalid".into()))?;
    let expected_shard =
        steadq_names::compute_shard(context.queue_id, &name.common.job_id, context.shard_count);
    if path_shard != expected_shard {
        return Err(VerificationError::Corrupt(
            "receipt shard placement mismatch".into(),
        ));
    }
    let bucket_number = steadq_names::bucket_from_hex(context.bucket)
        .ok_or_else(|| VerificationError::Corrupt("receipt bucket is invalid".into()))?;
    let bucket_start = bucket_number
        .checked_mul(context.terminal_bucket_width_ns)
        .ok_or_else(|| VerificationError::Corrupt("receipt bucket start overflows".into()))?;

    if let Some(expected) = expected {
        if !expected_name_matches(&name, expected) {
            return Err(VerificationError::Corrupt(
                "receipt operation identity mismatch".into(),
            ));
        }
    }

    let mut record = [0u8; COMPACT_RECEIPT_SIZE];
    fs::pread_exact(fd, &mut record, 0).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            VerificationError::Corrupt("receipt is shorter than its fixed record".into())
        } else {
            VerificationError::Io(error.to_string())
        }
    })?;

    let kind = if is_compact_receipt(file_size, &record) {
        let compact = CompactReceipt::decode(&record).map_err(|error| {
            VerificationError::Corrupt(format!("compact receipt decode: {error}"))
        })?;
        if !compact_path_fields_match(&compact, &name, bucket_start) {
            return Err(VerificationError::Corrupt(
                "compact receipt semantics do not match its path".into(),
            ));
        }
        if !payload_length_is_allowed(compact.original_payload_length, context.max_payload_length) {
            return Err(VerificationError::Corrupt(
                "compact receipt payload length exceeds queue limit".into(),
            ));
        }
        if let Some(expected) = expected {
            if !compact_evidence_matches(&compact, expected) {
                return Err(VerificationError::Corrupt(
                    "compact receipt evidence mismatch".into(),
                ));
            }
        }
        VerifiedReceiptKind::Compact
    } else {
        let job = verify_job_on_fd(fd)?;
        if !full_path_fields_match(&job.header, &name) {
            return Err(VerificationError::Corrupt(
                "full receipt header does not match its path".into(),
            ));
        }
        if !payload_length_is_allowed(job.header.payload_length, context.max_payload_length) {
            return Err(VerificationError::Corrupt(
                "full receipt payload length exceeds queue limit".into(),
            ));
        }
        if let Some(expected) = expected {
            if !full_evidence_matches(&job.header, expected) {
                return Err(VerificationError::Corrupt(
                    "full receipt evidence mismatch".into(),
                ));
            }
        }
        VerifiedReceiptKind::Full(job)
    };

    Ok(VerifiedReceipt {
        name,
        bucket_number,
        kind,
        device: stat.st_dev,
        inode: stat.st_ino,
    })
}

/// Verify the envelope and payload on an already-open fd. The fd must remain
/// open across any subsequent operation to prevent TOCTOU swap.
pub fn verify_job_on_fd(fd: BorrowedFd<'_>) -> Result<VerifiedJob, VerificationError> {
    let owned = fd
        .try_clone_to_owned()
        .map_err(|e| VerificationError::Io(e.to_string()))?;
    let header = read_and_verify_header(fd)?;
    let stat = verify_size(fd, &header, header.extension_header_length as usize)?;
    verify_payload(fd, &header, header.extension_header_length as usize)?;
    let ext = read_extension(fd, header.extension_header_length as usize)?;
    if !steadq_format::verify_envelope_digest(&header, &ext) {
        return Err(VerificationError::Corrupt(
            "envelope digest mismatch".into(),
        ));
    }
    Ok(VerifiedJob {
        fd: owned,
        header,
        extension: ext,
        device: stat.st_dev,
        inode: stat.st_ino,
        size: file_size(&stat)?,
    })
}

/// Light envelope-only verification (no payload hash). Used for inspection paths
/// that have not yet delivered payload to a consumer.
pub fn verify_envelope_on_fd(fd: BorrowedFd<'_>) -> Result<VerifiedJob, VerificationError> {
    let owned = fd
        .try_clone_to_owned()
        .map_err(|e| VerificationError::Io(e.to_string()))?;
    let header = read_and_verify_header(fd)?;
    let ext = read_extension(fd, header.extension_header_length as usize)?;
    if !steadq_format::verify_envelope_digest(&header, &ext) {
        return Err(VerificationError::Corrupt(
            "envelope digest mismatch".into(),
        ));
    }
    let stat = verify_size(fd, &header, ext.len())?;
    Ok(VerifiedJob {
        fd: owned,
        header,
        extension: ext,
        device: stat.st_dev,
        inode: stat.st_ino,
        size: file_size(&stat)?,
    })
}

fn read_and_verify_header(fd: BorrowedFd<'_>) -> Result<FixedHeader, VerificationError> {
    let mut header_buf = [0u8; 128];
    fs::pread_exact(fd, &mut header_buf, 0).map_err(|e| VerificationError::Io(e.to_string()))?;
    let header = FixedHeader::decode(&header_buf)
        .map_err(|e| VerificationError::Corrupt(format!("header decode: {e}")))?;
    let ext_len = header.extension_header_length as usize;
    if is_extension_too_large(ext_len) {
        return Err(VerificationError::Corrupt(
            "extension header too large".into(),
        ));
    }
    Ok(header)
}

fn read_extension(fd: BorrowedFd<'_>, ext_len: usize) -> Result<Vec<u8>, VerificationError> {
    let mut ext_buf = vec![0u8; ext_len];
    if is_extension_present(ext_len) {
        fs::pread_exact(fd, &mut ext_buf, 128).map_err(|e| VerificationError::Io(e.to_string()))?;
    }
    Ok(ext_buf)
}

fn verify_size(
    fd: BorrowedFd<'_>,
    header: &FixedHeader,
    ext_len: usize,
) -> Result<libc::stat, VerificationError> {
    let file_stat = fs::fstat(fd).map_err(|e| VerificationError::Io(e.to_string()))?;
    let actual_size = file_size(&file_stat)?;
    let expected_size = checked_total_size(ext_len, header.payload_length)?;
    if is_size_mismatch(expected_size, actual_size) {
        return Err(VerificationError::Corrupt(format!(
            "file size mismatch: expected {}, got {}",
            expected_size, file_stat.st_size
        )));
    }
    Ok(file_stat)
}

pub(crate) fn verify_payload(
    fd: BorrowedFd<'_>,
    header: &FixedHeader,
    ext_len: usize,
) -> Result<(), VerificationError> {
    let data_offset = (128 + ext_len) as u64;
    let mut hasher = sha2::Sha256::new();
    let mut offset = data_offset;
    let mut remaining = header.payload_length as usize;
    let buf_size = remaining.clamp(1, 65536);
    let mut buf = vec![0u8; buf_size];
    while remaining > 0 {
        let to_read = remaining.min(buf.len());
        let n = fs::pread(fd, &mut buf[..to_read], offset)
            .map_err(|e| VerificationError::Io(e.to_string()))?;
        if n == 0 {
            return Err(VerificationError::Corrupt("unexpected EOF".into()));
        }
        hasher.update(&buf[..n]);
        offset += n as u64;
        remaining -= n;
    }
    let computed: [u8; 32] = hasher.finalize().into();
    if !is_payload_digest_match(header, &computed) {
        return Err(VerificationError::PayloadCorrupt);
    }
    Ok(())
}

// helpers extracted for mutant killing
pub fn is_envelope_digest_valid(header: &FixedHeader, ext: &[u8]) -> bool {
    steadq_format::verify_envelope_digest(header, ext)
}

pub fn is_payload_digest_match(header: &FixedHeader, computed: &[u8; 32]) -> bool {
    &header.payload_digest == computed
}

pub fn is_extension_too_large(ext_len: usize) -> bool {
    ext_len > 65536
}

pub fn is_extension_present(ext_len: usize) -> bool {
    ext_len > 0
}

pub fn is_size_mismatch(expected: u64, actual: u64) -> bool {
    expected != actual
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd;

    use super::*;

    #[test]
    fn file_size_rejects_negative_and_accepts_zero() {
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(file_size(&stat).unwrap(), 0);

        stat.st_size = 1024;
        assert_eq!(file_size(&stat).unwrap(), 1024);

        stat.st_size = -1;
        assert!(file_size(&stat).is_err());

        stat.st_size = i64::MIN;
        assert!(file_size(&stat).is_err());
    }

    #[test]
    fn checked_total_size_rejects_overflow() {
        assert_eq!(checked_total_size(0, 0).unwrap(), 128);
        assert_eq!(checked_total_size(100, 200).unwrap(), 428);
        assert!(checked_total_size(usize::MAX, 0).is_err());
        assert!(checked_total_size(0, u64::MAX).is_err());
    }

    #[test]
    fn is_extension_too_large_table() {
        assert!(!is_extension_too_large(0));
        assert!(!is_extension_too_large(65536));
        assert!(is_extension_too_large(65537));
        assert!(is_extension_too_large(usize::MAX));
    }

    #[test]
    fn is_payload_digest_match_table() {
        let mut h = FixedHeader {
            format_minor: steadq_format::FORMAT_MINOR,
            extension_header_length: 0,
            payload_length: 0,
            flags: 0,
            digest_algorithm: 1,
            job_id: [1; 16],
            maximum_attempts: 1,
            created_at_unix_ns: 0,
            payload_digest: [0xAB; 32],
            envelope_digest: [0; 32],
        };
        assert!(is_payload_digest_match(&h, &[0xAB; 32]));
        assert!(!is_payload_digest_match(&h, &[0x00; 32]));
        h.payload_digest = [0x00; 32];
        assert!(is_payload_digest_match(&h, &[0x00; 32]));
        assert!(!is_payload_digest_match(&h, &[0x01; 32]));
    }

    #[test]
    fn verification_error_display() {
        assert_eq!(
            format!("{}", VerificationError::Io("boom".into())),
            "I/O: boom"
        );
        assert_eq!(
            format!("{}", VerificationError::Corrupt("bad".into())),
            "corrupt: bad"
        );
        assert_eq!(
            format!("{}", VerificationError::PayloadCorrupt),
            "payload corrupt"
        );
    }

    #[test]
    fn verification_error_into_core_error() {
        let e: Error = VerificationError::Io("x".into()).into();
        assert!(matches!(e, Error::IoFailure(_)));
        let e: Error = VerificationError::Corrupt("y".into()).into();
        assert!(matches!(e, Error::QueueCorrupt(_)));
        let e: Error = VerificationError::PayloadCorrupt.into();
        assert!(matches!(e, Error::PayloadCorrupt));
    }

    #[test]
    fn is_extension_present_table() {
        assert!(!is_extension_present(0));
        assert!(is_extension_present(1));
        assert!(is_extension_present(65536));
        assert!(is_extension_present(usize::MAX));
    }

    #[test]
    fn is_size_mismatch_table() {
        assert!(!is_size_mismatch(0, 0));
        assert!(!is_size_mismatch(100, 100));
        assert!(is_size_mismatch(100, 99));
        assert!(is_size_mismatch(100, 101));
        assert!(is_size_mismatch(u64::MAX, 0));
        assert!(is_size_mismatch(0, u64::MAX));
    }

    #[test]
    fn is_envelope_digest_valid_table() {
        let header = FixedHeader {
            format_minor: steadq_format::FORMAT_MINOR,
            extension_header_length: 0,
            payload_length: 0,
            flags: 0,
            digest_algorithm: 1,
            job_id: [0x11; 16],
            maximum_attempts: 1,
            created_at_unix_ns: 0,
            payload_digest: [0; 32],
            envelope_digest: [0; 32],
        };
        // empty extension with zero digest will not match unless header was computed for it;
        // we just verify predicate returns false for mismatched and is functionally wired.
        // Create a header whose envelope_digest is computed correctly for empty extension.
        let mut h = header.clone();
        let ext: Vec<u8> = vec![];
        // compute correct envelope: not trivial without helper, but we can verify that
        // the predicate is equivalent to steadq_format::verify_envelope_digest by checking
        // that negating the result matches the helper.
        let valid = is_envelope_digest_valid(&h, &ext);
        let expected = steadq_format::verify_envelope_digest(&h, &ext);
        assert_eq!(valid, expected);
        // flip a byte in envelope digest to make invalid
        h.envelope_digest = [0xFF; 32];
        assert!(!is_envelope_digest_valid(&h, &ext));
    }

    #[test]
    fn verified_job_retains_identity_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let file = std::fs::File::create(dir.path().join("job.sqj")).unwrap();
        let header = FixedHeader {
            format_minor: 1,
            extension_header_length: 0,
            payload_length: 4,
            flags: 0,
            digest_algorithm: 1,
            job_id: [0; 16],
            maximum_attempts: 1,
            created_at_unix_ns: 0,
            payload_digest: steadq_format::payload_digest(b"test"),
            envelope_digest: [0; 32],
        };
        let ext = vec![];
        let digest = steadq_format::envelope_digest(&header, &ext).unwrap();
        let header = FixedHeader {
            envelope_digest: digest,
            ..header
        };
        let buf = header.encode(&ext).unwrap();
        use std::os::unix::fs::FileExt;
        file.write_at(&buf, 0).unwrap();
        file.write_at(b"test", 128).unwrap();
        drop(file);

        let fd = std::fs::File::open(dir.path().join("job.sqj")).unwrap();
        let verified = verify_job_on_fd(fd.as_fd()).unwrap();
        let stat = fs::fstat(fd.as_fd()).unwrap();
        assert_eq!(verified.device(), stat.st_dev);
        assert_eq!(verified.inode(), stat.st_ino);
        assert_eq!(verified.size(), stat.st_size as u64);
        assert!(verified.identity_matches(&stat));

        // Mutated identity (wrong inode) must not match.
        let mut wrong = stat;
        wrong.st_ino = wrong.st_ino.wrapping_add(1);
        assert!(!verified.identity_matches(&wrong));

        // Extension accessor returns the verified bytes.
        assert!(verified.extension().is_empty());

        // The witness owns a dup'd fd that can read the same file.
        let witness_stat = fs::fstat(verified.as_fd()).unwrap();
        assert_eq!(witness_stat.st_dev, stat.st_dev);
        assert_eq!(witness_stat.st_ino, stat.st_ino);
    }

    #[test]
    fn verify_size_detects_mismatch_via_tmpfile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("size_test.raw");
        let header = FixedHeader {
            format_minor: steadq_format::FORMAT_MINOR,
            extension_header_length: 0,
            payload_length: 10,
            flags: 0,
            digest_algorithm: 1,
            job_id: [0x22; 16],
            maximum_attempts: 1,
            created_at_unix_ns: 0,
            payload_digest: [0; 32],
            envelope_digest: [0; 32],
        };
        let ext: Vec<u8> = vec![];
        let mut h = header.clone();
        h.envelope_digest = steadq_format::envelope_digest(&h, &ext).unwrap_or([0; 32]);
        let header_buf = h.encode(&ext).unwrap();
        std::fs::write(&path, header_buf).unwrap();
        let file = std::fs::OpenOptions::new().read(true).open(&path).unwrap();
        let res = verify_size(file.as_fd(), &h, 0);
        assert!(matches!(res, Err(VerificationError::Corrupt(_))));
        drop(file);
        let mut full = Vec::with_capacity(138);
        full.extend_from_slice(&header_buf);
        full.extend_from_slice(&[0u8; 10]);
        std::fs::write(&path, &full).unwrap();
        let file2 = std::fs::OpenOptions::new().read(true).open(&path).unwrap();
        let res2 = verify_size(file2.as_fd(), &h, 0);
        assert!(res2.is_ok());
    }

    #[test]
    fn compact_receipt_authenticates_path_and_operation_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let queue_id = [0x11; 16];
        let common = CommonFields {
            job_id: [0x22; 16],
            generation: 2,
            attempt: 1,
            maximum_attempts: 3,
        };
        let token = [0x33; 16];
        let envelope_digest = [0x44; 32];
        let shard_count = 64;
        let shard = steadq_names::compute_shard(&queue_id, &common.job_id, shard_count);
        let shard = steadq_names::shard_hex(shard);
        let bucket_number = 7;
        let bucket = steadq_names::bucket_hex(bucket_number);
        let width = 3_600_000_000_000;
        let filename = steadq_names::make_receipt_name(&queue_id, &bucket, &shard, &common, &token);
        let expected = ExpectedReceipt {
            common: common.clone(),
            token,
            envelope_digest,
            payload_length: 5,
        };
        let receipt = CompactReceipt {
            job_id: common.job_id,
            envelope_digest,
            final_attempt: common.attempt,
            lease_token: token,
            receipt_bucket_start_unix_ns: bucket_number * width,
            original_payload_length: 5,
        };
        let path = dir.path().join("receipt.rct");
        std::fs::write(&path, receipt.encode()).unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();

        let verify = |bucket: &str, shard: &str, filename: &str, expected: &ExpectedReceipt| {
            verify_receipt_on_fd(
                file.as_fd(),
                ReceiptContext {
                    queue_id: &queue_id,
                    shard_count,
                    terminal_bucket_width_ns: width,
                    max_payload_length: 1024,
                    bucket,
                    shard,
                    filename,
                },
                Some(expected),
            )
        };

        assert!(verify(&bucket, &shard, &filename, &expected).is_ok());
        assert!(verify("0000000000000008", &shard, &filename, &expected).is_err());
        assert!(verify(&bucket, "ffff", &filename, &expected).is_err());

        let mut wrong_common = expected.clone();
        wrong_common.common.generation += 1;
        assert!(verify(&bucket, &shard, &filename, &wrong_common).is_err());

        let mut wrong_token = expected.clone();
        wrong_token.token[0] ^= 1;
        assert!(verify(&bucket, &shard, &filename, &wrong_token).is_err());

        let mut wrong_envelope = expected.clone();
        wrong_envelope.envelope_digest[0] ^= 1;
        assert!(verify(&bucket, &shard, &filename, &wrong_envelope).is_err());

        let mut wrong_length = expected;
        wrong_length.payload_length += 1;
        assert!(verify(&bucket, &shard, &filename, &wrong_length).is_err());

        file.set_len(64).unwrap();
        assert!(matches!(
            verify(&bucket, &shard, &filename, &wrong_length),
            Err(VerificationError::Corrupt(ref message))
                if message == "receipt is shorter than its fixed record"
        ));
    }

    #[test]
    fn legacy_full_receipt_remains_strictly_verifiable() {
        let dir = tempfile::tempdir().unwrap();
        let queue_id = [0x11; 16];
        let common = CommonFields {
            job_id: [0x22; 16],
            generation: 2,
            attempt: 1,
            maximum_attempts: 3,
        };
        let token = [0x33; 16];
        let shard_count = 64;
        let shard = steadq_names::shard_hex(steadq_names::compute_shard(
            &queue_id,
            &common.job_id,
            shard_count,
        ));
        let bucket_number = 7;
        let bucket = steadq_names::bucket_hex(bucket_number);
        let width = 3_600_000_000_000;
        let filename = steadq_names::make_receipt_name(&queue_id, &bucket, &shard, &common, &token);
        let payload = b"hello";
        let mut header = FixedHeader {
            format_minor: 0,
            extension_header_length: 0,
            payload_length: payload.len() as u64,
            flags: 0,
            digest_algorithm: steadq_format::DIGEST_ALGORITHM_SHA256,
            job_id: common.job_id,
            maximum_attempts: common.maximum_attempts,
            created_at_unix_ns: 1_700_000_000_000_000_000,
            payload_digest: steadq_format::payload_digest(payload),
            envelope_digest: [0; 32],
        };
        header.envelope_digest = steadq_format::envelope_digest(&header, &[]).unwrap();
        let expected = ExpectedReceipt {
            common,
            token,
            envelope_digest: header.envelope_digest,
            payload_length: payload.len() as u64,
        };
        let mut bytes = header.encode(&[]).unwrap().to_vec();
        bytes.extend_from_slice(payload);
        let path = dir.path().join("legacy-full.rct");
        std::fs::write(&path, bytes).unwrap();
        let file = std::fs::File::open(path).unwrap();

        let verified = verify_receipt_on_fd(
            file.as_fd(),
            ReceiptContext {
                queue_id: &queue_id,
                shard_count,
                terminal_bucket_width_ns: width,
                max_payload_length: 1024,
                bucket: &bucket,
                shard: &shard,
                filename: &filename,
            },
            Some(&expected),
        )
        .unwrap();

        assert!(matches!(
            verified.kind,
            VerifiedReceiptKind::Full(ref job) if job.header.format_minor == 0
        ));
    }

    #[test]
    fn receipt_open_flags_are_exact() {
        assert_eq!(
            receipt_read_open_flags(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW
        );
        assert_eq!(
            receipt_write_open_flags(),
            libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW
        );

        let temp = tempfile::tempfile().unwrap();
        let stat = fs::fstat(temp.as_fd()).unwrap();
        assert!(receipt_path_identity_matches(
            &stat,
            stat.st_dev,
            stat.st_ino
        ));
        assert!(!receipt_path_identity_matches(
            &stat,
            stat.st_dev.wrapping_add(1),
            stat.st_ino
        ));
        assert!(!receipt_path_identity_matches(
            &stat,
            stat.st_dev,
            stat.st_ino.wrapping_add(1)
        ));
    }

    #[test]
    fn receipt_attempt_validation_boundaries() {
        for (attempt, maximum, expected) in [
            (0, 0, false),
            (0, 1, false),
            (1, 0, false),
            (1, 1, true),
            (2, 1, false),
            (u32::MAX, u32::MAX, true),
        ] {
            assert_eq!(receipt_attempt_is_valid(attempt, maximum), expected);
        }
    }

    #[test]
    fn compact_receipt_discrimination_requires_size_and_magic() {
        let mut record = [0u8; COMPACT_RECEIPT_SIZE];
        record[..RECEIPT_MAGIC.len()].copy_from_slice(RECEIPT_MAGIC);
        assert!(is_compact_receipt(COMPACT_RECEIPT_SIZE as u64, &record));
        assert!(!is_compact_receipt(
            COMPACT_RECEIPT_SIZE as u64 - 1,
            &record
        ));
        record[0] ^= 1;
        assert!(!is_compact_receipt(COMPACT_RECEIPT_SIZE as u64, &record));
    }

    #[test]
    fn payload_limit_is_inclusive() {
        assert!(payload_length_is_allowed(0, 0));
        assert!(payload_length_is_allowed(7, 7));
        assert!(!payload_length_is_allowed(8, 7));
        assert!(payload_length_is_allowed(u64::MAX, u64::MAX));
    }

    #[test]
    fn receipt_field_matchers_reject_each_mismatch() {
        let common = CommonFields {
            job_id: [1; 16],
            generation: 2,
            attempt: 1,
            maximum_attempts: 3,
        };
        let name = ReceiptName {
            common: common.clone(),
            token: [2; 16],
            tag: [3; 8],
        };
        let expected = ExpectedReceipt {
            common: common.clone(),
            token: name.token,
            envelope_digest: [4; 32],
            payload_length: 5,
        };
        assert!(expected_name_matches(&name, &expected));
        let mut changed = expected.clone();
        changed.common.generation += 1;
        assert!(!expected_name_matches(&name, &changed));
        changed = expected.clone();
        changed.token[0] ^= 1;
        assert!(!expected_name_matches(&name, &changed));

        let compact = CompactReceipt {
            job_id: common.job_id,
            envelope_digest: expected.envelope_digest,
            final_attempt: common.attempt,
            lease_token: name.token,
            receipt_bucket_start_unix_ns: 6,
            original_payload_length: expected.payload_length,
        };
        assert!(compact_path_fields_match(&compact, &name, 6));
        let mut changed_compact = compact.clone();
        changed_compact.job_id[0] ^= 1;
        assert!(!compact_path_fields_match(&changed_compact, &name, 6));
        changed_compact = compact.clone();
        changed_compact.lease_token[0] ^= 1;
        assert!(!compact_path_fields_match(&changed_compact, &name, 6));
        changed_compact = compact.clone();
        changed_compact.final_attempt += 1;
        assert!(!compact_path_fields_match(&changed_compact, &name, 6));
        assert!(!compact_path_fields_match(&compact, &name, 7));

        assert!(compact_evidence_matches(&compact, &expected));
        changed_compact = compact.clone();
        changed_compact.envelope_digest[0] ^= 1;
        assert!(!compact_evidence_matches(&changed_compact, &expected));
        changed_compact = compact.clone();
        changed_compact.original_payload_length += 1;
        assert!(!compact_evidence_matches(&changed_compact, &expected));

        let header = FixedHeader {
            format_minor: steadq_format::FORMAT_MINOR,
            extension_header_length: 0,
            payload_length: expected.payload_length,
            flags: 0,
            digest_algorithm: 1,
            job_id: common.job_id,
            maximum_attempts: common.maximum_attempts,
            created_at_unix_ns: 0,
            payload_digest: [0; 32],
            envelope_digest: expected.envelope_digest,
        };
        assert!(full_path_fields_match(&header, &name));
        let mut changed_header = header.clone();
        changed_header.job_id[0] ^= 1;
        assert!(!full_path_fields_match(&changed_header, &name));
        changed_header = header.clone();
        changed_header.maximum_attempts += 1;
        assert!(!full_path_fields_match(&changed_header, &name));

        assert!(full_evidence_matches(&header, &expected));
        changed_header = header.clone();
        changed_header.envelope_digest[0] ^= 1;
        assert!(!full_evidence_matches(&changed_header, &expected));
        changed_header = header;
        changed_header.payload_length += 1;
        assert!(!full_evidence_matches(&changed_header, &expected));
    }
}
