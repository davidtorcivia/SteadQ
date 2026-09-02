// SteadQ/1 canonical filename parsing, formatting, name tags, and shard math.

use sha2::{Digest, Sha256};
use std::fmt::Write as _;

// ---------- Hex helpers ----------

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    push_hex(&mut encoded, bytes);
    encoded
}

fn push_hex(encoded: &mut String, bytes: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for &byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
}

fn from_hex_digit_lower(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

fn from_hex_pair_lower(chunk: &[u8]) -> Option<u8> {
    Some((from_hex_digit_lower(chunk[0])? << 4) | from_hex_digit_lower(chunk[1])?)
}

/// Decode exactly `2 * N` lowercase hex digits.
fn hex_decode_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N {
        return None;
    }
    let mut out = [0u8; N];
    for (byte, chunk) in out.iter_mut().zip(s.as_bytes().chunks(2)) {
        *byte = from_hex_pair_lower(chunk)?;
    }
    Some(out)
}

pub fn hex_decode_16(s: &str) -> Option<[u8; 16]> {
    hex_decode_array(s)
}

pub fn hex_decode_u64(s: &str) -> Option<u64> {
    hex_decode_array(s).map(u64::from_be_bytes)
}

pub fn hex_decode_u32(s: &str) -> Option<u32> {
    hex_decode_array(s).map(u32::from_be_bytes)
}

pub fn hex_decode_u16(s: &str) -> Option<u16> {
    hex_decode_array(s).map(u16::from_be_bytes)
}

fn hex_u64(v: u64) -> String {
    format!("{v:016x}")
}

fn hex_u16(v: u16) -> String {
    format!("{v:04x}")
}

// ---------- States ----------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum State {
    Ready,
    Leased,
    Delayed,
    Receipt,
    Dead,
    Quarantine,
}

impl State {
    pub fn dir_name(&self) -> &'static str {
        match self {
            State::Ready => "ready",
            State::Leased => "leased",
            State::Delayed => "delayed",
            State::Receipt => "receipts",
            State::Dead => "dead",
            State::Quarantine => "quarantine",
        }
    }
}

// ---------- Name tag ----------

/// Compute the 64-bit name integrity tag.
/// tag = first 8 bytes of SHA256("SteadQ-1-name\0" || queue_id || ascii_context)
pub fn compute_name_tag(queue_id: &[u8; 16], canonical_context: &str) -> [u8; 8] {
    compute_name_tag_parts(queue_id, &[canonical_context])
}

fn compute_name_tag_parts(queue_id: &[u8; 16], context_parts: &[&str]) -> [u8; 8] {
    let mut hasher = Sha256::new();
    hasher.update(b"SteadQ-1-name\0");
    hasher.update(queue_id);
    for part in context_parts {
        hasher.update(part.as_bytes());
    }
    let result = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&result[..8]);
    out
}

// ---------- Shard derivation ----------

/// shard_hash = SHA256("SteadQ-1-shard\0" || queue_id || job_id)
/// shard = low_log2(shard_count)_bits(shard_hash)
pub fn compute_shard(queue_id: &[u8; 16], job_id: &[u8; 16], shard_count: u32) -> u32 {
    let mut hasher = Sha256::new();
    hasher.update(b"SteadQ-1-shard\0");
    hasher.update(queue_id);
    hasher.update(job_id);
    let result = hasher.finalize();

    let k = shard_count.trailing_zeros();
    let val = u32::from_be_bytes(result[..4].try_into().unwrap());
    val & ((1u32 << k) - 1)
}

pub fn shard_hex(shard: u32) -> String {
    format!("{shard:04x}")
}

pub fn shard_from_hex(s: &str) -> Option<u32> {
    hex_decode_u16(s).map(u32::from)
}

// ---------- Shard scan permutation ----------

/// scan_hash = SHA256("SteadQ-1-scan\0" || queue_id || boot_id || worker_nonce || u64be(scan_round))
/// start = u64(h[0:8]) & (S - 1)
/// stride = (u64(h[8:16]) | 1) & (S - 1), min 1
pub fn shard_scan_params(
    queue_id: &[u8; 16],
    boot_id: &[u8; 16],
    worker_nonce: &[u8; 16],
    scan_round: u64,
    shard_count: u32,
) -> (u32, u32) {
    let mut hasher = Sha256::new();
    hasher.update(b"SteadQ-1-scan\0");
    hasher.update(queue_id);
    hasher.update(boot_id);
    hasher.update(worker_nonce);
    hasher.update(scan_round.to_be_bytes());
    let result = hasher.finalize();

    let mask = shard_count - 1;
    let start = u64::from_be_bytes(result[..8].try_into().unwrap()) & mask as u64;
    let mut stride = (u64::from_be_bytes(result[8..16].try_into().unwrap()) | 1) & mask as u64;
    if stride == 0 {
        stride = 1;
    }
    (start as u32, stride as u32)
}

/// The i-th shard: (start + stride·i) mod shard_count.
pub fn shard_at(start: u32, stride: u32, i: u32, shard_count: u32) -> u32 {
    let mask = shard_count - 1;
    (start.wrapping_add(stride.wrapping_mul(i))) & mask
}

// ---------- Bucket names ----------

pub fn bucket_hex(bucket: u64) -> String {
    format!("{bucket:016x}")
}

pub fn bucket_from_hex(s: &str) -> Option<u64> {
    if s.len() != 16 {
        return None;
    }
    hex_decode_u64(s)
}

// ---------- Boot ID ----------

pub fn boot_id_string(raw: &str) -> String {
    raw.trim().to_string()
}

pub fn format_boot_id(bytes: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

pub fn boot_id_bytes(s: &str) -> Option<[u8; 16]> {
    // canonical 36-char lowercase uuid: 8-4-4-4-12 hex digits
    if s.len() != 36 {
        return None;
    }
    let bytes = s.as_bytes();
    for &pos in &[8, 13, 18, 23] {
        if bytes[pos] != b'-' {
            return None;
        }
    }
    let mut decoded = [0u8; 16];
    let mut nibble_index = 0usize;
    for (index, &byte) in bytes.iter().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            continue;
        }
        let nibble = from_hex_digit_lower(byte)?;
        let output = &mut decoded[nibble_index / 2];
        if nibble_index.is_multiple_of(2) {
            *output = nibble << 4;
        } else {
            *output |= nibble;
        }
        nibble_index += 1;
    }
    Some(decoded)
}

// ---------- Canonical filenames ----------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommonFields {
    pub job_id: [u8; 16],
    pub generation: u64,
    pub attempt: u32,
    pub maximum_attempts: u32,
}

impl CommonFields {
    fn base_name(&self) -> String {
        let mut name = String::with_capacity(70);
        push_hex(&mut name, &self.job_id);
        write!(
            name,
            ".g{:016x}.a{:08x}.m{:08x}",
            self.generation, self.attempt, self.maximum_attempts
        )
        .expect("writing to a String cannot fail");
        name
    }
}

// ---------- Canonical context reconstruction ----------
// Single source of truth for name-tag context; all consumers (resolver,
// fsck, recovery, duplicate-ack) must use these instead of reconstructing it.

impl ReadyName {
    /// Reconstruct the exact canonical context used by the writer.
    pub fn canonical_context(&self, shard_hex: &str) -> String {
        ready_context(shard_hex, &self.common.base_name())
    }

    /// Authenticate the name tag against the queue ID.
    pub fn authenticate_tag(&self, queue_id: &[u8; 16], shard_hex: &str) -> bool {
        let base = self.common.base_name();
        compute_name_tag_parts(queue_id, &["ready/-/-/", shard_hex, "/", &base]) == self.tag
    }
}

impl LeasedName {
    fn leased_base(&self) -> String {
        let mut base = self.common.base_name();
        base.reserve(104);
        base.push_str(".o");
        push_hex(&mut base, &self.boot_id);
        write!(
            base,
            ".b{:016x}.w{:016x}.t",
            self.boottime_deadline_ns, self.wall_deadline_ns
        )
        .expect("writing to a String cannot fail");
        push_hex(&mut base, &self.token);
        base
    }

    /// Reconstruct the exact canonical context used by the writer.
    pub fn canonical_context(&self, boot_id: &str, bucket: &str, shard_hex: &str) -> String {
        leased_context(boot_id, bucket, shard_hex, &self.leased_base())
    }

    /// Authenticate the name tag against the queue ID.
    pub fn authenticate_tag(
        &self,
        queue_id: &[u8; 16],
        boot_id: &str,
        bucket: &str,
        shard_hex: &str,
    ) -> bool {
        let base = self.leased_base();
        compute_name_tag_parts(
            queue_id,
            &["leased/", boot_id, "/", bucket, "/", shard_hex, "/", &base],
        ) == self.tag
    }
}

impl DelayedName {
    fn delayed_base(&self) -> String {
        let mut base = self.common.base_name();
        write!(base, ".d{:016x}", self.not_before_ns).expect("writing to a String cannot fail");
        base
    }

    /// Reconstruct the exact canonical context used by the writer.
    pub fn canonical_context(&self, bucket: &str, shard_hex: &str) -> String {
        delayed_context(bucket, shard_hex, &self.delayed_base())
    }

    /// Authenticate the name tag against the queue ID.
    pub fn authenticate_tag(&self, queue_id: &[u8; 16], bucket: &str, shard_hex: &str) -> bool {
        let base = self.delayed_base();
        compute_name_tag_parts(
            queue_id,
            &["delayed/-/", bucket, "/", shard_hex, "/", &base],
        ) == self.tag
    }
}

impl DeadName {
    fn dead_base(&self) -> String {
        let mut base = self.common.base_name();
        write!(base, ".x{:04x}", self.reason).expect("writing to a String cannot fail");
        base
    }

    /// Reconstruct the exact canonical context used by the writer.
    pub fn canonical_context(&self, bucket: &str, shard_hex: &str) -> String {
        terminal_context(State::Dead, bucket, shard_hex, &self.dead_base())
    }

    /// Authenticate the name tag against the queue ID.
    pub fn authenticate_tag(&self, queue_id: &[u8; 16], bucket: &str, shard_hex: &str) -> bool {
        let base = self.dead_base();
        compute_name_tag_parts(
            queue_id,
            &[
                State::Dead.dir_name(),
                "/-/",
                bucket,
                "/",
                shard_hex,
                "/",
                &base,
            ],
        ) == self.tag
    }
}

impl ReceiptName {
    fn receipt_base(&self) -> String {
        let mut base = self.common.base_name();
        base.push_str(".t");
        push_hex(&mut base, &self.token);
        base
    }

    /// Reconstruct the exact canonical context used by the writer.
    pub fn canonical_context(&self, bucket: &str, shard_hex: &str) -> String {
        terminal_context(State::Receipt, bucket, shard_hex, &self.receipt_base())
    }

    /// Authenticate the name tag against the queue ID.
    pub fn authenticate_tag(&self, queue_id: &[u8; 16], bucket: &str, shard_hex: &str) -> bool {
        let base = self.receipt_base();
        compute_name_tag_parts(
            queue_id,
            &[
                State::Receipt.dir_name(),
                "/-/",
                bucket,
                "/",
                shard_hex,
                "/",
                &base,
            ],
        ) == self.tag
    }
}

// Ready: <job-id>.g<gen>.a<att>.m<max>.k<tag>.sqj
pub fn ready_filename(fields: &CommonFields, tag: &[u8; 8]) -> String {
    tagged_filename(fields.base_name(), tag, ".sqj")
}

// Delayed: <job-id>.g<gen>.a<att>.m<max>.d<ns>.k<tag>.sqj
pub fn delayed_filename(fields: &CommonFields, not_before_ns: u64, tag: &[u8; 8]) -> String {
    let mut base = fields.base_name();
    write!(base, ".d{not_before_ns:016x}").expect("writing to a String cannot fail");
    tagged_filename(base, tag, ".sqj")
}

// Dead: <job-id>.g<gen>.a<att>.m<max>.x<reason>.k<tag>.sqj
pub fn dead_filename(fields: &CommonFields, reason: u16, tag: &[u8; 8]) -> String {
    let mut base = fields.base_name();
    write!(base, ".x{reason:04x}").expect("writing to a String cannot fail");
    tagged_filename(base, tag, ".sqj")
}

// Receipt: <job-id>.g<gen>.a<att>.m<max>.t<token>.k<tag>.rct
pub fn receipt_filename(fields: &CommonFields, token: &[u8; 16], tag: &[u8; 8]) -> String {
    let mut base = fields.base_name();
    base.push_str(".t");
    push_hex(&mut base, token);
    tagged_filename(base, tag, ".rct")
}

// Leased: <job-id>.g<gen>.a<att>.m<max>.o<boot>.b<boottime_dl>.w<wall_dl>.t<token>.k<tag>.sqj
pub fn leased_filename(
    fields: &CommonFields,
    boot_id: &[u8; 16],
    boottime_deadline_ns: u64,
    wall_deadline_ns: u64,
    token: &[u8; 16],
    tag: &[u8; 8],
) -> String {
    let mut base = fields.base_name();
    base.push_str(".o");
    push_hex(&mut base, boot_id);
    write!(
        base,
        ".b{boottime_deadline_ns:016x}.w{wall_deadline_ns:016x}.t"
    )
    .expect("writing to a String cannot fail");
    push_hex(&mut base, token);
    tagged_filename(base, tag, ".sqj")
}

fn tagged_filename(mut base: String, tag: &[u8; 8], extension: &str) -> String {
    // ".k" + 16 tag hex chars + 4-byte extension
    base.reserve(22);
    base.push_str(".k");
    push_hex(&mut base, tag);
    base.push_str(extension);
    base
}

// Temp: <created-boottime-ns-hex>.<random-128-bit-hex>.tmp
pub fn temp_filename(created_boottime_ns: u64, random: &[u8; 16]) -> String {
    format!(
        "{}.{}.tmp",
        hex_u64(created_boottime_ns),
        hex_encode(random)
    )
}

// Quarantine: q<quarantine-id>.x<reason>.raw
pub fn quarantine_filename(quarantine_id: &[u8; 16], reason: u16) -> String {
    format!("q{}.x{}.raw", hex_encode(quarantine_id), hex_u16(reason))
}

// ---------- High-level canonical builders ----------
// Single writer-side source: callers supply semantic fields; canonical text,
// context, and tag derive here. Production code must use these instead of
// composing *_context directly.

pub fn make_ready_name(queue_id: &[u8; 16], shard_hex: &str, common: &CommonFields) -> String {
    let base = common.base_name();
    let tag = compute_name_tag_parts(queue_id, &["ready/-/-/", shard_hex, "/", &base]);
    tagged_filename(base, &tag, ".sqj")
}

pub fn make_delayed_name(
    queue_id: &[u8; 16],
    bucket_hex: &str,
    shard_hex: &str,
    common: &CommonFields,
    not_before_ns: u64,
) -> String {
    let mut base = common.base_name();
    write!(base, ".d{not_before_ns:016x}").expect("writing to a String cannot fail");
    let tag = compute_name_tag_parts(
        queue_id,
        &["delayed/-/", bucket_hex, "/", shard_hex, "/", &base],
    );
    tagged_filename(base, &tag, ".sqj")
}

#[allow(clippy::too_many_arguments)]
pub fn make_leased_name(
    queue_id: &[u8; 16],
    boot_id: &str,
    bucket_hex: &str,
    shard_hex: &str,
    common: &CommonFields,
    boottime_deadline_ns: u64,
    wall_deadline_ns: u64,
    token: &[u8; 16],
) -> Option<String> {
    let boot_bytes = boot_id_bytes(boot_id)?;
    let mut base = common.base_name();
    base.push_str(".o");
    push_hex(&mut base, &boot_bytes);
    write!(
        base,
        ".b{boottime_deadline_ns:016x}.w{wall_deadline_ns:016x}.t"
    )
    .expect("writing to a String cannot fail");
    push_hex(&mut base, token);
    let tag = compute_name_tag_parts(
        queue_id,
        &[
            "leased/", boot_id, "/", bucket_hex, "/", shard_hex, "/", &base,
        ],
    );
    Some(tagged_filename(base, &tag, ".sqj"))
}

pub fn make_receipt_name(
    queue_id: &[u8; 16],
    bucket_hex: &str,
    shard_hex: &str,
    common: &CommonFields,
    token: &[u8; 16],
) -> String {
    let mut base = common.base_name();
    base.push_str(".t");
    push_hex(&mut base, token);
    let tag = compute_name_tag_parts(
        queue_id,
        &[
            State::Receipt.dir_name(),
            "/-/",
            bucket_hex,
            "/",
            shard_hex,
            "/",
            &base,
        ],
    );
    tagged_filename(base, &tag, ".rct")
}

pub fn make_dead_name(
    queue_id: &[u8; 16],
    bucket_hex: &str,
    shard_hex: &str,
    common: &CommonFields,
    reason: u16,
) -> String {
    let mut base = common.base_name();
    write!(base, ".x{reason:04x}").expect("writing to a String cannot fail");
    let tag = compute_name_tag_parts(
        queue_id,
        &[
            State::Dead.dir_name(),
            "/-/",
            bucket_hex,
            "/",
            shard_hex,
            "/",
            &base,
        ],
    );
    tagged_filename(base, &tag, ".sqj")
}

// ---------- Canonical context for name tag ----------

/// Build the canonical context string used for name tag computation.
/// Format: <state>/<boot-id-or-dash>/<bucket-or-dash>/<shard-hex>/<filename-without-k-and-ext>
pub fn ready_context(shard_hex: &str, filename_without_tag_ext: &str) -> String {
    format!("ready/-/-/{shard_hex}/{filename_without_tag_ext}")
}

pub fn leased_context(
    boot_id: &str,
    bucket: &str,
    shard_hex: &str,
    filename_without_tag_ext: &str,
) -> String {
    format!("leased/{boot_id}/{bucket}/{shard_hex}/{filename_without_tag_ext}")
}

pub fn delayed_context(bucket: &str, shard_hex: &str, filename_without_tag_ext: &str) -> String {
    format!("delayed/-/{bucket}/{shard_hex}/{filename_without_tag_ext}")
}

pub fn terminal_context(
    state: State,
    bucket: &str,
    shard_hex: &str,
    filename_without_tag_ext: &str,
) -> String {
    format!(
        "{}/-/{}/{}/{}",
        state.dir_name(),
        bucket,
        shard_hex,
        filename_without_tag_ext
    )
}

// ---------- Filename parser ----------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadyName {
    pub common: CommonFields,
    pub tag: [u8; 8],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelayedName {
    pub common: CommonFields,
    pub not_before_ns: u64,
    pub tag: [u8; 8],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeadName {
    pub common: CommonFields,
    pub reason: u16,
    pub tag: [u8; 8],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptName {
    pub common: CommonFields,
    pub token: [u8; 16],
    pub tag: [u8; 8],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeasedName {
    pub common: CommonFields,
    pub boot_id: [u8; 16],
    pub boottime_deadline_ns: u64,
    pub wall_deadline_ns: u64,
    pub token: [u8; 16],
    pub tag: [u8; 8],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TempName {
    pub created_boottime_ns: u64,
    pub random: [u8; 16],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuarantineName {
    pub quarantine_id: [u8; 16],
    pub reason: u16,
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("invalid extension")]
    BadExtension,
    #[error("missing field {0}")]
    MissingField(&'static str),
    #[error("invalid hex field {0}")]
    BadHex(&'static str),
    #[error("malformed filename")]
    Malformed,
    #[error("non-ASCII byte in filename")]
    NonAscii,
}

/// Filenames are ASCII protocol data.
/// Rejects any byte > 127 or embedded NUL.
fn assert_ascii(s: &str) -> Result<(), ParseError> {
    if s.is_ascii() && !s.contains('\0') {
        Ok(())
    } else {
        Err(ParseError::NonAscii)
    }
}

/// Strip a single ASCII prefix byte. The prefix is ASCII, so the remainder
/// starts on a char boundary.
fn strip_tag(part: &str, prefix: u8) -> Result<&str, ParseError> {
    match part.as_bytes() {
        [first, rest @ ..] if *first == prefix && !rest.is_empty() => Ok(&part[1..]),
        _ => Err(ParseError::Malformed),
    }
}

/// Strictly parse a tagged hex value with a single-character prefix.
/// Returns Err on wrong prefix, wrong length, or non-canonical hex.
fn parse_tagged_hex_u64(part: &str, prefix: u8) -> Result<u64, ParseError> {
    hex_decode_u64(strip_tag(part, prefix)?).ok_or(ParseError::BadHex("u64"))
}

fn parse_tagged_hex_u32(part: &str, prefix: u8) -> Result<u32, ParseError> {
    hex_decode_u32(strip_tag(part, prefix)?).ok_or(ParseError::BadHex("u32"))
}

fn parse_tagged_hex_u16(part: &str, prefix: u8) -> Result<u16, ParseError> {
    hex_decode_u16(strip_tag(part, prefix)?).ok_or(ParseError::BadHex("u16"))
}

fn parse_tagged_hex_16(part: &str, prefix: u8) -> Result<[u8; 16], ParseError> {
    hex_decode_16(strip_tag(part, prefix)?).ok_or(ParseError::BadHex("16"))
}

fn parse_tag(part: &str) -> Result<[u8; 8], ParseError> {
    hex_decode_array(strip_tag(part, b'k')?).ok_or(ParseError::BadHex("k"))
}

/// Parse common fields from the first four dot-separated parts:
/// job_id, g{gen}, a{att}, m{max}
/// Returns (common, remaining_parts).
fn parse_common_strict<'a>(
    parts: &'a [&'a str],
) -> Result<(CommonFields, &'a [&'a str]), ParseError> {
    if parts.len() < 4 {
        return Err(ParseError::Malformed);
    }
    let job_id = hex_decode_16(parts[0]).ok_or(ParseError::BadHex("job_id"))?;
    let generation = parse_tagged_hex_u64(parts[1], b'g')?;
    let attempt = parse_tagged_hex_u32(parts[2], b'a')?;
    let maximum_attempts = parse_tagged_hex_u32(parts[3], b'm')?;
    Ok((
        CommonFields {
            job_id,
            generation,
            attempt,
            maximum_attempts,
        },
        &parts[4..],
    ))
}

/// Ready: job_id.g{gen}.a{att}.m{max}.k{tag}.sqj
/// Exactly 5 dot-separated parts before .sqj.
pub fn parse_ready(filename: &str) -> Result<ReadyName, ParseError> {
    assert_ascii(filename)?;
    let filename = filename
        .strip_suffix(".sqj")
        .ok_or(ParseError::BadExtension)?;
    let parts: Vec<&str> = filename.split('.').collect();
    if parts.len() != 5 {
        return Err(ParseError::Malformed);
    }
    let (common, rest) = parse_common_strict(&parts)?;
    if rest.len() != 1 {
        return Err(ParseError::Malformed);
    }
    let tag = parse_tag(rest[0])?;
    Ok(ReadyName { common, tag })
}

/// Delayed: job_id.g{gen}.a{att}.m{max}.d{ns}.k{tag}.sqj
/// Exactly 6 dot-separated parts before .sqj.
pub fn parse_delayed(filename: &str) -> Result<DelayedName, ParseError> {
    assert_ascii(filename)?;
    let filename = filename
        .strip_suffix(".sqj")
        .ok_or(ParseError::BadExtension)?;
    let parts: Vec<&str> = filename.split('.').collect();
    if parts.len() != 6 {
        return Err(ParseError::Malformed);
    }
    let (common, rest) = parse_common_strict(&parts)?;
    if rest.len() != 2 {
        return Err(ParseError::Malformed);
    }
    let not_before_ns = parse_tagged_hex_u64(rest[0], b'd')?;
    let tag = parse_tag(rest[1])?;
    Ok(DelayedName {
        common,
        not_before_ns,
        tag,
    })
}

/// Dead: job_id.g{gen}.a{att}.m{max}.x{reason}.k{tag}.sqj
/// Exactly 6 dot-separated parts before .sqj.
pub fn parse_dead(filename: &str) -> Result<DeadName, ParseError> {
    assert_ascii(filename)?;
    let filename = filename
        .strip_suffix(".sqj")
        .ok_or(ParseError::BadExtension)?;
    let parts: Vec<&str> = filename.split('.').collect();
    if parts.len() != 6 {
        return Err(ParseError::Malformed);
    }
    let (common, rest) = parse_common_strict(&parts)?;
    if rest.len() != 2 {
        return Err(ParseError::Malformed);
    }
    let reason = parse_tagged_hex_u16(rest[0], b'x')?;
    let tag = parse_tag(rest[1])?;
    Ok(DeadName {
        common,
        reason,
        tag,
    })
}

/// Receipt: job_id.g{gen}.a{att}.m{max}.t{token}.k{tag}.rct
/// Exactly 6 dot-separated parts before .rct.
pub fn parse_receipt(filename: &str) -> Result<ReceiptName, ParseError> {
    assert_ascii(filename)?;
    let filename = filename
        .strip_suffix(".rct")
        .ok_or(ParseError::BadExtension)?;
    let parts: Vec<&str> = filename.split('.').collect();
    if parts.len() != 6 {
        return Err(ParseError::Malformed);
    }
    let (common, rest) = parse_common_strict(&parts)?;
    if rest.len() != 2 {
        return Err(ParseError::Malformed);
    }
    let token = parse_tagged_hex_16(rest[0], b't')?;
    let tag = parse_tag(rest[1])?;
    Ok(ReceiptName { common, token, tag })
}

/// Leased: job_id.g{gen}.a{att}.m{max}.o{boot}.b{boot_dl}.w{wall_dl}.t{token}.k{tag}.sqj
/// Exactly 9 dot-separated parts before .sqj.
pub fn parse_leased(filename: &str) -> Result<LeasedName, ParseError> {
    assert_ascii(filename)?;
    let filename = filename
        .strip_suffix(".sqj")
        .ok_or(ParseError::BadExtension)?;
    let parts: Vec<&str> = filename.split('.').collect();
    if parts.len() != 9 {
        return Err(ParseError::Malformed);
    }
    let (common, rest) = parse_common_strict(&parts)?;
    if rest.len() != 5 {
        return Err(ParseError::Malformed);
    }
    let boot_id = parse_tagged_hex_16(rest[0], b'o')?;
    let boottime_deadline_ns = parse_tagged_hex_u64(rest[1], b'b')?;
    let wall_deadline_ns = parse_tagged_hex_u64(rest[2], b'w')?;
    let token = parse_tagged_hex_16(rest[3], b't')?;
    let tag = parse_tag(rest[4])?;
    Ok(LeasedName {
        common,
        boot_id,
        boottime_deadline_ns,
        wall_deadline_ns,
        token,
        tag,
    })
}

/// Temp: {boottime}.{random}.tmp
/// Exactly 2 dot-separated parts before .tmp.
pub fn parse_temp(filename: &str) -> Result<TempName, ParseError> {
    assert_ascii(filename)?;
    let filename = filename
        .strip_suffix(".tmp")
        .ok_or(ParseError::BadExtension)?;
    let parts: Vec<&str> = filename.split('.').collect();
    if parts.len() != 2 {
        return Err(ParseError::Malformed);
    }
    let created_boottime_ns = hex_decode_u64(parts[0]).ok_or(ParseError::BadHex("boottime"))?;
    let random = hex_decode_16(parts[1]).ok_or(ParseError::BadHex("random"))?;
    Ok(TempName {
        created_boottime_ns,
        random,
    })
}

/// Quarantine: q{id}.x{reason}.raw
/// Exactly 2 dot-separated parts before .raw (after the leading 'q' on first).
pub fn parse_quarantine(filename: &str) -> Result<QuarantineName, ParseError> {
    assert_ascii(filename)?;
    let filename = filename
        .strip_suffix(".raw")
        .ok_or(ParseError::BadExtension)?;
    let parts: Vec<&str> = filename.split('.').collect();
    if parts.len() != 2 {
        return Err(ParseError::Malformed);
    }
    // First part: q{32hex}
    let first_bytes = parts[0].as_bytes();
    if first_bytes.len() != 33 || first_bytes[0] != b'q' {
        return Err(ParseError::Malformed);
    }
    let id_hex = std::str::from_utf8(&first_bytes[1..]).map_err(|_| ParseError::NonAscii)?;
    let quarantine_id = hex_decode_16(id_hex).ok_or(ParseError::BadHex("id"))?;
    // Second part: x{4hex}
    let reason = parse_tagged_hex_u16(parts[1], b'x')?;
    Ok(QuarantineName {
        quarantine_id,
        reason,
    })
}

pub fn hex_decode_32(s: &str) -> Option<[u8; 32]> {
    hex_decode_array(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_width_hex_decoders_accept_exact_lowercase_only() {
        assert_eq!(shard_from_hex("0000"), Some(0));
        assert_eq!(shard_from_hex("0001"), Some(1));
        assert_eq!(shard_from_hex("03ef"), Some(0x03ef));
        assert_eq!(shard_from_hex("ffff"), Some(0xffff));
        for bad in ["03EF", "3ef", "003ef", "", "zzzz"] {
            assert_eq!(shard_from_hex(bad), None, "{bad}");
        }

        let digest: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3));
        let encoded = hex_encode(&digest);
        assert_eq!(hex_decode_32(&encoded), Some(digest));
        assert_eq!(hex_decode_32(&encoded.to_uppercase()), None);
        assert_eq!(hex_decode_32(&encoded[..62]), None);
        assert_eq!(hex_decode_32(&format!("{encoded}00")), None);

        assert_eq!(hex_decode_u16("0102"), Some(0x0102));
        assert_eq!(hex_decode_u32("01020304"), Some(0x0102_0304));
        assert_eq!(
            hex_decode_u64("0102030405060708"),
            Some(0x0102_0304_0506_0708)
        );
        assert_eq!(hex_decode_u64("010203040506070"), None);
    }

    #[test]
    fn strip_tag_requires_prefix_and_nonempty_remainder() {
        assert_eq!(strip_tag("kab", b'k').unwrap(), "ab");
        assert_eq!(strip_tag("kcaf\u{e9}", b'k').unwrap(), "caf\u{e9}");
        for bad in ["k", "", "xab"] {
            assert!(
                matches!(strip_tag(bad, b'k'), Err(ParseError::Malformed)),
                "{bad:?}"
            );
        }
    }

    fn test_queue_id() -> [u8; 16] {
        [0x42; 16]
    }

    fn test_job_id() -> [u8; 16] {
        [0xAB; 16]
    }

    #[test]
    fn ready_filename_round_trip() {
        let common = CommonFields {
            job_id: test_job_id(),
            generation: 1,
            attempt: 0,
            maximum_attempts: 3,
        };
        let tag = [0x11; 8];
        let filename = ready_filename(&common, &tag);
        let parsed = parse_ready(&filename).unwrap();
        assert_eq!(parsed.common, common);
        assert_eq!(parsed.tag, tag);
    }

    #[test]
    fn leased_filename_round_trip() {
        let common = CommonFields {
            job_id: test_job_id(),
            generation: 2,
            attempt: 1,
            maximum_attempts: 5,
        };
        let tag = [0x22; 8];
        let token = [0x33; 16];
        let boot = [0x11; 16];
        let filename = leased_filename(&common, &boot, 999_999_999, 1_000_000_000, &token, &tag);
        let parsed = parse_leased(&filename).unwrap();
        assert_eq!(parsed.common, common);
        assert_eq!(parsed.boot_id, boot);
        assert_eq!(parsed.boottime_deadline_ns, 999_999_999);
        assert_eq!(parsed.wall_deadline_ns, 1_000_000_000);
        assert_eq!(parsed.token, token);
        assert_eq!(parsed.tag, tag);
    }

    #[test]
    fn delayed_filename_round_trip() {
        let common = CommonFields {
            job_id: test_job_id(),
            generation: 0,
            attempt: 0,
            maximum_attempts: 1,
        };
        let tag = [0x44; 8];
        let filename = delayed_filename(&common, 1_700_000_000_000_000_000, &tag);
        let parsed = parse_delayed(&filename).unwrap();
        assert_eq!(parsed.common, common);
        assert_eq!(parsed.not_before_ns, 1_700_000_000_000_000_000);
        assert_eq!(parsed.tag, tag);
    }

    #[test]
    fn dead_filename_round_trip() {
        let common = CommonFields {
            job_id: test_job_id(),
            generation: 5,
            attempt: 3,
            maximum_attempts: 3,
        };
        let tag = [0x55; 8];
        let filename = dead_filename(&common, 0x0004, &tag);
        let parsed = parse_dead(&filename).unwrap();
        assert_eq!(parsed.common, common);
        assert_eq!(parsed.reason, 0x0004);
        assert_eq!(parsed.tag, tag);
    }

    #[test]
    fn receipt_filename_round_trip() {
        let common = CommonFields {
            job_id: test_job_id(),
            generation: 4,
            attempt: 2,
            maximum_attempts: 5,
        };
        let tag = [0x66; 8];
        let token = [0x77; 16];
        let filename = receipt_filename(&common, &token, &tag);
        let parsed = parse_receipt(&filename).unwrap();
        assert_eq!(parsed.common, common);
        assert_eq!(parsed.token, token);
        assert_eq!(parsed.tag, tag);
    }

    #[test]
    fn temp_filename_round_trip() {
        let random = [0x88; 16];
        let filename = temp_filename(1_700_000_000_000_000_000, &random);
        let parsed = parse_temp(&filename).unwrap();
        assert_eq!(parsed.created_boottime_ns, 1_700_000_000_000_000_000);
        assert_eq!(parsed.random, random);
    }

    #[test]
    fn quarantine_filename_round_trip() {
        let id = [0x99; 16];
        let filename = quarantine_filename(&id, 0x0001);
        let parsed = parse_quarantine(&filename).unwrap();
        assert_eq!(parsed.quarantine_id, id);
        assert_eq!(parsed.reason, 0x0001);
    }

    #[test]
    fn shard_computation() {
        let qid = test_queue_id();
        let jid = test_job_id();
        let shard = compute_shard(&qid, &jid, 64);
        assert!(shard < 64);
        let shard2 = compute_shard(&qid, &jid, 64);
        assert_eq!(shard, shard2);
    }

    #[test]
    fn shard_scan_visits_all() {
        let qid = test_queue_id();
        let boot = [0xFE; 16];
        let nonce = [0xDC; 16];
        let count = 64u32;
        let (start, stride) = shard_scan_params(&qid, &boot, &nonce, 0, count);

        let mut visited = vec![false; count as usize];
        for i in 0..count {
            let s = shard_at(start, stride, i, count);
            assert!(!visited[s as usize], "shard {s} visited twice");
            visited[s as usize] = true;
        }
        assert!(visited.iter().all(|&v| v));
    }

    #[test]
    fn boot_id_parse() {
        let s = "12345678-1234-1234-1234-123456789abc";
        let bytes = boot_id_bytes(s).unwrap();
        assert_eq!(bytes[0], 0x12);
        assert_eq!(bytes[15], 0xbc);
    }

    #[test]
    fn boot_id_rejects_uppercase() {
        let s = "12345678-1234-1234-1234-123456789ABC";
        assert!(boot_id_bytes(s).is_none());
    }

    #[test]
    fn format_boot_id_round_trips_canonical_uuid() {
        let bytes = [
            0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78,
            0x9a, 0xbc,
        ];
        let formatted = format_boot_id(&bytes);
        assert_eq!(formatted, "12345678-1234-1234-1234-123456789abc");
        assert_eq!(boot_id_bytes(&formatted), Some(bytes));
    }

    #[test]
    fn hex_decode_rejects_uppercase() {
        // ABNF requires lowercase hex only: %x30-39 / %x61-66
        assert!(hex_decode_16("ABCDEF0123456789ABCDEF0123456789").is_none());
        assert!(hex_decode_u64("000000000000000F").is_none());
        assert!(hex_decode_u32("0000000F").is_none());
        assert!(hex_decode_u16("000F").is_none());
        assert!(hex_decode_16("abcdef0123456789abcdef0123456789").is_some());
        assert!(hex_decode_u64("000000000000000f").is_some());
    }

    #[test]
    fn name_tag_deterministic() {
        let qid = test_queue_id();
        let ctx = "ready/-/-/000f/test";
        let tag1 = compute_name_tag(&qid, ctx);
        let tag2 = compute_name_tag(&qid, ctx);
        assert_eq!(tag1, tag2);
    }

    #[test]
    fn ready_filename_tag_authenticates() {
        let qid = test_queue_id();
        let jid = test_job_id();
        let shard = compute_shard(&qid, &jid, 64);
        let common = CommonFields {
            job_id: jid,
            generation: 0,
            attempt: 0,
            maximum_attempts: 3,
        };
        let sh = shard_hex(shard);
        let filename = make_ready_name(&qid, &sh, &common);
        let parsed = parse_ready(&filename).unwrap();
        assert!(parsed.authenticate_tag(&qid, &sh));
        assert!(!parsed.authenticate_tag(&qid, "0000"));
    }

    #[test]
    fn parse_rejects_bad_ext() {
        assert!(parse_ready("foo.bar").is_err());
    }

    // Canonical parser tests: reject unknown, duplicate, reordered fields.
    #[test]
    fn ready_rejects_extra_field() {
        let common = CommonFields {
            job_id: [0xAB; 16],
            generation: 0,
            attempt: 0,
            maximum_attempts: 3,
        };
        let tag = [0xFF; 8];
        let fname = ready_filename(&common, &tag);
        let bad = fname.replace(".k", ".e00.k");
        assert!(parse_ready(&bad).is_err(), "should reject extra field");
    }

    #[test]
    fn ready_rejects_reordered_fields() {
        let common = CommonFields {
            job_id: [0xAB; 16],
            generation: 1,
            attempt: 2,
            maximum_attempts: 3,
        };
        let tag = [0xFF; 8];
        let fname = ready_filename(&common, &tag);
        let parts: Vec<&str> = fname.split('.').collect();
        // parts: [jobid, g..., a..., m..., k..., "sqj"]
        let swapped = format!(
            "{}.{}.{}.{}.{}.{}",
            parts[0], parts[2], parts[1], parts[3], parts[4], parts[5]
        );
        assert!(parse_ready(&swapped).is_err(), "should reject reordered");
    }

    #[test]
    fn ready_rejects_duplicate_field() {
        let common = CommonFields {
            job_id: [0xAB; 16],
            generation: 1,
            attempt: 2,
            maximum_attempts: 3,
        };
        let tag = [0xFF; 8];
        let fname = ready_filename(&common, &tag);
        let parts: Vec<&str> = fname.split('.').collect();
        let duped = format!(
            "{}.{}.{}.{}.{}.{}.{}",
            parts[0], parts[1], parts[1], parts[2], parts[3], parts[4], parts[5]
        );
        assert!(parse_ready(&duped).is_err(), "should reject duplicate");
    }

    #[test]
    fn ready_round_trip_canonical() {
        let common = CommonFields {
            job_id: [0xAB; 16],
            generation: 42,
            attempt: 7,
            maximum_attempts: 3,
        };
        let tag = [0xDE; 8];
        let fname = ready_filename(&common, &tag);
        let parsed = parse_ready(&fname).unwrap();
        assert_eq!(parsed.common, common);
        assert_eq!(parsed.tag, tag);
        let re_formatted = ready_filename(&parsed.common, &parsed.tag);
        assert_eq!(fname, re_formatted, "round trip must produce same name");
    }

    #[test]
    fn leased_round_trip_canonical() {
        let common = CommonFields {
            job_id: [0xCD; 16],
            generation: 99,
            attempt: 5,
            maximum_attempts: 10,
        };
        let tag = [0x11; 8];
        let token = [0x22; 16];
        let boot = [0x44; 16];
        let fname = leased_filename(&common, &boot, 1_000_000_000, 2_000_000_000, &token, &tag);
        let parsed = parse_leased(&fname).unwrap();
        assert_eq!(parsed.common, common);
        assert_eq!(parsed.tag, tag);
        assert_eq!(parsed.token, token);
        assert_eq!(parsed.boot_id, boot);
        assert_eq!(parsed.boottime_deadline_ns, 1_000_000_000);
        assert_eq!(parsed.wall_deadline_ns, 2_000_000_000);
        let re_formatted = leased_filename(
            &parsed.common,
            &parsed.boot_id,
            parsed.boottime_deadline_ns,
            parsed.wall_deadline_ns,
            &parsed.token,
            &parsed.tag,
        );
        assert_eq!(fname, re_formatted);
    }

    #[test]
    fn ready_rejects_leased_name() {
        let common = CommonFields {
            job_id: [0xAB; 16],
            generation: 1,
            attempt: 1,
            maximum_attempts: 3,
        };
        let tag = [0xFF; 8];
        let token = [0xEE; 16];
        let leased_name = leased_filename(
            &common,
            &[0x01; 16],
            1_000_000_000,
            2_000_000_000,
            &token,
            &tag,
        );
        assert!(
            parse_ready(&leased_name).is_err(),
            "should reject leased name as ready"
        );
    }

    #[test]
    fn leased_rejects_ready_name() {
        let common = CommonFields {
            job_id: [0xAB; 16],
            generation: 0,
            attempt: 0,
            maximum_attempts: 3,
        };
        let tag = [0xFF; 8];
        let ready_name = ready_filename(&common, &tag);
        assert!(
            parse_leased(&ready_name).is_err(),
            "should reject ready name as leased"
        );
    }

    #[test]
    fn non_ascii_filename_does_not_panic() {
        // Too many fields: fails, but must not panic.
        let bad = "abababababababababababababababab.g0000000000000000.a00000000.m00000003.kffffffffffffffff.test.sqj";
        assert!(parse_ready(bad).is_err());
        // Byte with high bit set
        let bad2 = "\u{80}bababababababababababababababab.g0000000000000000.a00000000.m00000003.kffffffffffffffff.sqj";
        let _ = parse_ready(bad2);
    }

    #[test]
    fn parsers_reject_uppercase_hex() {
        let common = CommonFields {
            job_id: [0xAB; 16],
            generation: 0,
            attempt: 0,
            maximum_attempts: 3,
        };
        let tag = [0xFF; 8];
        let fname = ready_filename(&common, &tag);
        let parsed = parse_ready(&fname).unwrap();
        assert_eq!(parsed.common, common);
        let bad = fname.to_uppercase().replace(".SQJ", ".sqj");
        assert!(parse_ready(&bad).is_err(), "uppercase hex must be rejected");
    }
    #[test]
    fn ready_name_length_is_92() {
        let common = CommonFields {
            job_id: [0xAB; 16],
            generation: u64::MAX,
            attempt: u32::MAX,
            maximum_attempts: u32::MAX,
        };
        let tag = [0xFF; 8];
        let name = ready_filename(&common, &tag);
        assert_eq!(
            name.len(),
            92,
            "ready name must be exactly 92 bytes, got {}",
            name.len()
        );
    }

    #[test]
    fn delayed_name_length_is_110() {
        let common = CommonFields {
            job_id: [0xAB; 16],
            generation: u64::MAX,
            attempt: u32::MAX,
            maximum_attempts: u32::MAX,
        };
        let tag = [0xFF; 8];
        let name = delayed_filename(&common, u64::MAX, &tag);
        assert_eq!(
            name.len(),
            110,
            "delayed name must be exactly 110 bytes, got {}",
            name.len()
        );
    }

    #[test]
    fn dead_name_length_is_98() {
        let common = CommonFields {
            job_id: [0xAB; 16],
            generation: u64::MAX,
            attempt: u32::MAX,
            maximum_attempts: u32::MAX,
        };
        let tag = [0xFF; 8];
        let name = dead_filename(&common, 0xFFFF, &tag);
        assert_eq!(
            name.len(),
            98,
            "dead name must be exactly 98 bytes, got {}",
            name.len()
        );
    }

    #[test]
    fn receipt_name_length_is_126() {
        let common = CommonFields {
            job_id: [0xAB; 16],
            generation: u64::MAX,
            attempt: u32::MAX,
            maximum_attempts: u32::MAX,
        };
        let tag = [0xFF; 8];
        let token = [0xFF; 16];
        let name = receipt_filename(&common, &token, &tag);
        assert_eq!(
            name.len(),
            126,
            "receipt name must be exactly 126 bytes, got {}",
            name.len()
        );
    }

    #[test]
    fn leased_name_length_is_196() {
        let common = CommonFields {
            job_id: [0xAB; 16],
            generation: u64::MAX,
            attempt: u32::MAX,
            maximum_attempts: u32::MAX,
        };
        let tag = [0xFF; 8];
        let token = [0xFF; 16];
        let name = leased_filename(&common, &[0xFF; 16], u64::MAX, u64::MAX, &token, &tag);
        assert_eq!(
            name.len(),
            196,
            "leased name must be exactly 196 bytes, got {}",
            name.len()
        );
    }

    #[test]
    fn temp_name_length_is_53() {
        let random = [0xFF; 16];
        let name = temp_filename(u64::MAX, &random);
        assert_eq!(
            name.len(),
            53,
            "temp name must be exactly 53 bytes, got {}",
            name.len()
        );
    }

    #[test]
    fn quarantine_name_length_is_43() {
        let id = [0xFF; 16];
        let name = quarantine_filename(&id, 0xFFFF);
        assert_eq!(
            name.len(),
            43,
            "quarantine name must be exactly 43 bytes, got {}",
            name.len()
        );
    }

    #[test]
    fn all_names_fit_within_255() {
        let max = 196; // leased is longest
        assert!(max <= 255, "longest name {max} exceeds NAME_MAX 255");
        assert_eq!(255 - max, 59, "remaining budget must be 59");
    }

    // ===== authenticate_tag tests =====

    fn make_common() -> CommonFields {
        CommonFields {
            job_id: test_job_id(),
            generation: 1,
            attempt: 1,
            maximum_attempts: 3,
        }
    }

    #[test]
    fn ready_authenticate_tag_round_trip() {
        let qid = test_queue_id();
        let common = make_common();
        let shard = "01ab";
        let ctx = ready_context(shard, &common.base_name());
        let tag = compute_name_tag(&qid, &ctx);
        let name = ReadyName {
            common: common.clone(),
            tag,
        };
        assert!(name.authenticate_tag(&qid, shard));
        assert!(!name.authenticate_tag(&[0xFF; 16], shard));
        assert!(!name.authenticate_tag(&qid, "0000"));
    }

    #[test]
    fn leased_authenticate_tag_round_trip() {
        let qid = test_queue_id();
        let common = make_common();
        let boot = "00000000-0000-0000-0000-000000000000";
        let bucket = "0000000000000001";
        let shard = "01ab";
        let token = [0xCD; 16];
        let name = LeasedName {
            common: common.clone(),
            boot_id: [0; 16],
            boottime_deadline_ns: 30000000000,
            wall_deadline_ns: 1234567890,
            token,
            tag: [0; 8],
        };
        let ctx = name.canonical_context(boot, bucket, shard);
        let tag = compute_name_tag(&qid, &ctx);
        let name = LeasedName {
            common: common.clone(),
            boot_id: [0; 16],
            boottime_deadline_ns: 30000000000,
            wall_deadline_ns: 1234567890,
            token,
            tag,
        };
        assert!(name.authenticate_tag(&qid, boot, bucket, shard));
        assert!(!name.authenticate_tag(&[0xFF; 16], boot, bucket, shard));
        assert!(!name.authenticate_tag(&qid, "wrong", bucket, shard));
    }

    #[test]
    fn delayed_authenticate_tag_round_trip() {
        let qid = test_queue_id();
        let common = make_common();
        let bucket = "0000000000000001";
        let shard = "01ab";
        let nb: u64 = 9999999999;
        let name = DelayedName {
            common: common.clone(),
            not_before_ns: nb,
            tag: [0; 8],
        };
        let ctx = name.canonical_context(bucket, shard);
        let tag = compute_name_tag(&qid, &ctx);
        let name = DelayedName {
            common: common.clone(),
            not_before_ns: nb,
            tag,
        };
        assert!(name.authenticate_tag(&qid, bucket, shard));
        assert!(!name.authenticate_tag(&[0xFF; 16], bucket, shard));
        assert!(!name.authenticate_tag(&qid, "0000000000000000", shard));
    }

    #[test]
    fn dead_authenticate_tag_round_trip() {
        let qid = test_queue_id();
        let common = make_common();
        let bucket = "0000000000000001";
        let shard = "01ab";
        let name = DeadName {
            common: common.clone(),
            reason: 0x0004,
            tag: [0; 8],
        };
        let ctx = name.canonical_context(bucket, shard);
        let tag = compute_name_tag(&qid, &ctx);
        let name = DeadName {
            common: common.clone(),
            reason: 0x0004,
            tag,
        };
        assert!(name.authenticate_tag(&qid, bucket, shard));
        assert!(!name.authenticate_tag(&[0xFF; 16], bucket, shard));
    }

    #[test]
    fn receipt_authenticate_tag_round_trip() {
        let qid = test_queue_id();
        let common = make_common();
        let bucket = "0000000000000001";
        let shard = "01ab";
        let token = [0xEE; 16];
        let name = ReceiptName {
            common: common.clone(),
            token,
            tag: [0; 8],
        };
        let ctx = name.canonical_context(bucket, shard);
        let tag = compute_name_tag(&qid, &ctx);
        let name = ReceiptName {
            common: common.clone(),
            token,
            tag,
        };
        assert!(name.authenticate_tag(&qid, bucket, shard));
        assert!(!name.authenticate_tag(&[0xFF; 16], bucket, shard));
    }

    // ===== canonical_context output tests =====

    #[test]
    fn ready_canonical_context_format() {
        let common = make_common();
        let name = ReadyName {
            common: common.clone(),
            tag: [0; 8],
        };
        let ctx = name.canonical_context("01ab");
        assert!(ctx.starts_with("ready/-/-/01ab/"));
        assert!(ctx.contains(&common.base_name()));
        // Non-empty and correct structure
        assert!(!ctx.is_empty());
    }

    #[test]
    fn leased_canonical_context_format() {
        let common = make_common();
        let name = LeasedName {
            common: common.clone(),
            boot_id: [0; 16],
            boottime_deadline_ns: 30000000000,
            wall_deadline_ns: 1234567890,
            token: [0xCD; 16],
            tag: [0; 8],
        };
        let ctx = name.canonical_context("boot-id", "bucket1", "01ab");
        assert!(ctx.starts_with("leased/boot-id/bucket1/01ab/"));
        assert!(ctx.contains(".b"));
        assert!(ctx.contains(".w"));
        assert!(ctx.contains(".t"));
        assert!(!ctx.is_empty());
    }

    #[test]
    fn delayed_canonical_context_format() {
        let common = make_common();
        let name = DelayedName {
            common: common.clone(),
            not_before_ns: 9999999999,
            tag: [0; 8],
        };
        let ctx = name.canonical_context("bucket1", "01ab");
        assert!(ctx.starts_with("delayed/-/bucket1/01ab/"));
        assert!(ctx.contains(".d"));
        assert!(!ctx.is_empty());
    }

    #[test]
    fn dead_canonical_context_format() {
        let common = make_common();
        let name = DeadName {
            common: common.clone(),
            reason: 0x0004,
            tag: [0; 8],
        };
        let ctx = name.canonical_context("bucket1", "01ab");
        assert!(ctx.starts_with("dead/-/bucket1/01ab/"));
        assert!(ctx.contains(".x"));
        assert!(!ctx.is_empty());
    }

    #[test]
    fn receipt_canonical_context_format() {
        let common = make_common();
        let name = ReceiptName {
            common: common.clone(),
            token: [0xEE; 16],
            tag: [0; 8],
        };
        let ctx = name.canonical_context("bucket1", "01ab");
        assert!(ctx.starts_with("receipts/-/bucket1/01ab/"));
        assert!(ctx.contains(".t"));
        assert!(!ctx.is_empty());
    }

    #[test]
    fn make_ready_name_round_trip() {
        let qid = test_queue_id();
        let common = make_common();
        let shard = "01ab";
        let name = make_ready_name(&qid, shard, &common);
        let parsed = parse_ready(&name).expect("make_ready_name should be parseable");
        assert_eq!(parsed.common, common);
        assert!(parsed.authenticate_tag(&qid, shard));
    }

    #[test]
    fn make_delayed_name_round_trip() {
        let qid = test_queue_id();
        let common = make_common();
        let bucket = "0000000000000005";
        let shard = "02cd";
        let not_before = 1_700_000_000_000_000_000u64;
        let name = make_delayed_name(&qid, bucket, shard, &common, not_before);
        let parsed = parse_delayed(&name).expect("make_delayed_name parse");
        assert_eq!(parsed.common, common);
        assert_eq!(parsed.not_before_ns, not_before);
        assert!(parsed.authenticate_tag(&qid, bucket, shard));
    }

    #[test]
    fn make_leased_name_round_trip() {
        let qid = test_queue_id();
        let common = make_common();
        let boot = "12345678-1234-1234-1234-123456789abc";
        let bucket = "000000000000000a";
        let shard = "03ef";
        let token = [0xAB; 16];
        let name = make_leased_name(
            &qid,
            boot,
            bucket,
            shard,
            &common,
            3_000_000_000,
            4_000_000_000,
            &token,
        )
        .unwrap();
        let parsed = parse_leased(&name).expect("make_leased_name parse");
        assert!(make_leased_name(
            &qid,
            "not-a-boot-id",
            bucket,
            shard,
            &common,
            3_000_000_000,
            4_000_000_000,
            &token,
        )
        .is_none());
        assert_eq!(parsed.common, common);
        assert_eq!(parsed.boottime_deadline_ns, 3_000_000_000);
        assert_eq!(parsed.wall_deadline_ns, 4_000_000_000);
        assert_eq!(parsed.token, token);
        assert_eq!(parsed.boot_id, boot_id_bytes(boot).unwrap());
        assert!(parsed.authenticate_tag(&qid, boot, bucket, shard));
    }

    #[test]
    fn make_receipt_name_round_trip() {
        let qid = test_queue_id();
        let common = make_common();
        let bucket = "0000000000000007";
        let shard = "04aa";
        let token = [0xCD; 16];
        let name = make_receipt_name(&qid, bucket, shard, &common, &token);
        let parsed = parse_receipt(&name).expect("make_receipt_name parse");
        assert_eq!(parsed.common, common);
        assert_eq!(parsed.token, token);
        assert!(parsed.authenticate_tag(&qid, bucket, shard));
    }

    #[test]
    fn make_dead_name_round_trip() {
        let qid = test_queue_id();
        let common = make_common();
        let bucket = "0000000000000009";
        let shard = "05bb";
        let name = make_dead_name(&qid, bucket, shard, &common, 0x0004);
        let parsed = parse_dead(&name).expect("make_dead_name parse");
        assert_eq!(parsed.common, common);
        assert_eq!(parsed.reason, 0x0004);
        assert!(parsed.authenticate_tag(&qid, bucket, shard));
    }

    #[test]
    fn compute_shard_known_value() {
        let qid = [0x42; 16];
        let jid = [0xAB; 16];
        // Pinned value; catches changes to the domain string or hash extraction.
        assert_eq!(compute_shard(&qid, &jid, 64), 36);
    }

    #[test]
    fn shard_scan_params_known_value() {
        let qid = [0x42; 16];
        let boot = [0u8; 16];
        let nonce = [0u8; 16];
        // Pinned value; catches changes to the domain string or hash extraction.
        let (start, stride) = shard_scan_params(&qid, &boot, &nonce, 0, 64);
        assert_eq!(start, 46);
        assert_eq!(stride, 23);
    }
}
