// SteadQ/1 C ABI.
// The queue handle is wrapped in a Mutex for thread safety; all FFI
// functions catch panics to prevent process termination.
//
// Doc comments here are the header documentation: cbindgen copies them
// into include/steadq.h.
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(clippy::unnecessary_cast)]

use std::cell::RefCell;
use std::ffi::{CStr, CString, OsStr};
use std::os::raw::{c_char, c_int, c_uint};
use std::os::unix::ffi::OsStrExt;
use std::ptr;
use std::sync::Mutex;

use steadq_core::{
    CreateOptions, EnqueueInput, EnqueueOutcome, Error, LeaseInfo, LeaseOutcome, OpenOptions,
    Queue, RenewOutcome, ResolutionOutcome, TransitionOutcome, TransitionTicket,
    VerifiedPayloadReader, WorkBudget,
};

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
    static LAST_TICKET: RefCell<Option<CString>> = const { RefCell::new(None) };
}

fn clear_last_error() {
    LAST_ERROR.with(|cell| {
        *cell.borrow_mut() = None;
    });
}

/// Only the mutating calls clear the slot, so the pointer from
/// steadq_last_ticket_json stays valid through the steadq_resolve call that
/// consumes it. Enqueue clears it too: its indeterminate outcome carries no
/// transition ticket, and a stale one must not be mistaken for it.
fn clear_last_ticket() {
    LAST_TICKET.with(|cell| {
        *cell.borrow_mut() = None;
    });
}

fn store_last_ticket(json: Vec<u8>) {
    LAST_TICKET.with(|cell| {
        *cell.borrow_mut() = CString::new(json).ok();
    });
}

/// Stash the ticket of an indeterminate outcome for steadq_last_ticket_json.
fn set_last_ticket(ticket: &TransitionTicket) {
    if let Ok(json) = ticket.to_json() {
        store_last_ticket(json);
    }
}

fn set_last_error(msg: &str) {
    LAST_ERROR.with(|cell| {
        *cell.borrow_mut() = CString::new(msg).ok();
    });
}

fn classify_init_error(e: std::io::Error) -> Error {
    match e.kind() {
        std::io::ErrorKind::Unsupported => Error::UnsupportedFilesystem,
        std::io::ErrorKind::PermissionDenied => Error::PermissionDenied,
        std::io::ErrorKind::StorageFull | std::io::ErrorKind::QuotaExceeded => {
            Error::ResourceExhausted
        }
        std::io::ErrorKind::AlreadyExists
        | std::io::ErrorKind::InvalidInput
        | std::io::ErrorKind::InvalidData => Error::InvalidInput(e.to_string()),
        std::io::ErrorKind::WouldBlock => Error::MaintenanceBusy,
        _ => Error::IoFailure(e.to_string()),
    }
}

/// Centralized error-to-code mapping.
fn error_to_code(e: &Error) -> c_int {
    match e {
        Error::QueueCorrupt(_) => STEADQ_CORRUPTION,
        Error::PayloadCorrupt => STEADQ_CORRUPTION,
        Error::UnsupportedFilesystem | Error::UnsupportedFormat => STEADQ_UNSUPPORTED,
        Error::PermissionDenied => STEADQ_PERMISSION_DENIED,
        Error::ResourceExhausted | Error::StateExhausted => STEADQ_RESOURCE_EXHAUSTED,
        Error::IoFailure(_) => STEADQ_IO_FAILURE,
        Error::InvalidClock => STEADQ_IO_FAILURE,
        Error::MaintenanceBusy => STEADQ_NOT_COMMITTED,
        Error::QueuePoisoned(_) => STEADQ_CORRUPTION,
        Error::IdentityCollision => STEADQ_NOT_COMMITTED,
        Error::InvalidInput(_) | Error::InvalidTicket(_) => STEADQ_NOT_COMMITTED,
    }
}

/// Result codes matching the spec exit codes.
pub const STEADQ_OK: c_int = 0;
pub const STEADQ_NOT_COMMITTED: c_int = 1;
pub const STEADQ_INDETERMINATE: c_int = 2;
pub const STEADQ_CORRUPTION: c_int = 3;
pub const STEADQ_RESOURCE_EXHAUSTED: c_int = 4;
pub const STEADQ_PERMISSION_DENIED: c_int = 5;
pub const STEADQ_IO_FAILURE: c_int = 6;
pub const STEADQ_UNSUPPORTED: c_int = 64;

/// Opaque queue handle. Safe to share across C threads.
pub struct SteadqQueue {
    inner: Mutex<Queue>,
}

/// Opaque lease handle. Not thread-safe; use from one thread at a time.
pub struct SteadqLease {
    inner: LeaseInfo,
}

/// Opaque payload reader handle. Not thread-safe.
pub struct SteadqPayloadReader {
    inner: VerifiedPayloadReader,
}

/// Job ID (128 bits = 16 bytes).
#[repr(C)]
pub struct SteadqJobId {
    pub bytes: [u8; 16],
}

/// Get last error as a C string. Returns pointer to thread-local storage.
/// The pointer is valid until the next SteadQ call on the same thread.
/// Do not free.
#[no_mangle]
pub extern "C" fn steadq_last_error() -> *const c_char {
    LAST_ERROR.with(|cell| {
        let b = cell.borrow();
        b.as_ref().map_or(ptr::null(), |cs| cs.as_ptr())
    })
}

/// After steadq_lease, steadq_renew, steadq_ack, steadq_retry, or
/// steadq_bury returns STEADQ_INDETERMINATE, the transition ticket as JSON
/// for steadq_resolve. Returns NULL when the last such call left no ticket,
/// and after an indeterminate steadq_enqueue, which has no transition
/// ticket. Thread-local; valid until the next steadq_enqueue, steadq_lease,
/// steadq_renew, steadq_ack, steadq_retry, or steadq_bury on the same
/// thread, so it may be passed straight into steadq_resolve. Do not free.
#[no_mangle]
pub extern "C" fn steadq_last_ticket_json() -> *const c_char {
    LAST_TICKET.with(|cell| {
        let b = cell.borrow();
        b.as_ref().map_or(ptr::null(), |cs| cs.as_ptr())
    })
}

/// No-op for ABI compatibility: steadq_last_error() returns thread-local
/// storage that does not need to be freed.
#[no_mangle]
pub extern "C" fn steadq_free_string(_s: *const c_char) {}

/// Query the ABI version.
#[no_mangle]
pub extern "C" fn steadq_abi_version() -> c_uint {
    1
}

/// A C path as a filesystem path: any bytes but NUL, UTF-8 or not.
fn c_path<'a>(path: *const c_char) -> &'a std::path::Path {
    std::path::Path::new(OsStr::from_bytes(
        unsafe { CStr::from_ptr(path) }.to_bytes(),
    ))
}

/// Create a queue at `path` with `shard_count` shards and open it.
/// Returns NULL on failure with the reason in steadq_last_error(); the
/// message starts with the error class (for example "resource exhausted"
/// or "unsupported filesystem") followed by the system error.
#[no_mangle]
pub extern "C" fn steadq_init(path: *const c_char, shard_count: c_uint) -> *mut SteadqQueue {
    clear_last_error();
    if path.is_null() {
        set_last_error("null path");
        return ptr::null_mut();
    }
    let result = std::panic::catch_unwind(|| {
        let path = c_path(path);
        let opts = CreateOptions {
            shard_count,
            ..Default::default()
        };
        if let Err(e) = Queue::init(path, &opts) {
            let detail = e.to_string();
            let class = classify_init_error(e).to_string();
            // Unit classes such as "resource exhausted" drop the errno text.
            return Err(if class.contains(&detail) {
                class
            } else {
                format!("{class}: {detail}")
            });
        }
        Queue::open(path, &OpenOptions::default()).map_err(leak_error)
    });
    match result {
        Ok(Ok(q)) => Box::into_raw(Box::new(SteadqQueue {
            inner: Mutex::new(q),
        })),
        Ok(Err(message)) => {
            set_last_error(&message);
            ptr::null_mut()
        }
        Err(_) => {
            set_last_error("panic in steadq_init");
            ptr::null_mut()
        }
    }
}

/// Open an existing queue. Returns NULL on failure with the reason in
/// steadq_last_error().
#[no_mangle]
pub extern "C" fn steadq_open(path: *const c_char) -> *mut SteadqQueue {
    clear_last_error();
    if path.is_null() {
        set_last_error("null path");
        return ptr::null_mut();
    }
    let result = std::panic::catch_unwind(|| Queue::open(c_path(path), &OpenOptions::default()));
    match result {
        Ok(Ok(q)) => Box::into_raw(Box::new(SteadqQueue {
            inner: Mutex::new(q),
        })),
        Ok(Err(e)) => {
            set_last_error(&leak_error(e));
            ptr::null_mut()
        }
        Err(_) => {
            set_last_error("panic in steadq_open");
            ptr::null_mut()
        }
    }
}

/// Close a queue handle.
#[no_mangle]
pub extern "C" fn steadq_close(queue: *mut SteadqQueue) {
    if !queue.is_null() {
        unsafe { drop(Box::from_raw(queue)) };
    }
}

/// Enqueue a job. Writes the job ID to `job_id_out` (zeroed first) when
/// non-NULL. Returns STEADQ_OK when committed; STEADQ_INDETERMINATE when
/// the job may or may not be durable (job_id_out is still set; there is no
/// transition ticket); otherwise an error code with steadq_last_error().
#[no_mangle]
pub extern "C" fn steadq_enqueue(
    queue: *mut SteadqQueue,
    payload: *const u8,
    payload_len: usize,
    content_type: *const c_char,
    max_attempts: c_uint,
    job_id_out: *mut SteadqJobId,
) -> c_int {
    clear_last_error();
    clear_last_ticket();
    if !job_id_out.is_null() {
        unsafe { (*job_id_out).bytes = [0; 16] };
    }
    if queue.is_null() {
        set_last_error("null queue");
        return STEADQ_NOT_COMMITTED;
    }
    let result = std::panic::catch_unwind(|| {
        let queue = unsafe { &*queue };
        let mut guard = match queue.inner.lock() {
            Ok(guard) => guard,
            Err(_) => {
                set_last_error("queue mutex poisoned (previous panic during operation)");
                return STEADQ_CORRUPTION;
            }
        };
        let payload = if payload.is_null() {
            if payload_len != 0 {
                set_last_error("null payload with nonzero length");
                return STEADQ_NOT_COMMITTED;
            }
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(payload, payload_len) }.to_vec()
        };
        let content_type = if content_type.is_null() {
            "application/octet-stream".to_string()
        } else {
            match unsafe { CStr::from_ptr(content_type) }.to_str() {
                Ok(s) => s.to_string(),
                Err(_) => {
                    set_last_error("invalid UTF-8 in content_type");
                    return STEADQ_NOT_COMMITTED;
                }
            }
        };
        match guard.enqueue(EnqueueInput {
            maximum_attempts: max_attempts,
            content_type,
            payload,
            ..Default::default()
        }) {
            EnqueueOutcome::Committed(ticket) => {
                if !job_id_out.is_null() {
                    unsafe { (*job_id_out).bytes = ticket.job_id };
                }
                STEADQ_OK
            }
            EnqueueOutcome::Deferred(ticket) => {
                if !job_id_out.is_null() {
                    unsafe { (*job_id_out).bytes = ticket.job_id };
                }
                set_last_error("enqueue directory durability is deferred");
                STEADQ_INDETERMINATE
            }
            EnqueueOutcome::NotCommitted(_, e) => {
                let code = error_to_code(&e);
                set_last_error(&leak_error(e));
                code
            }
            EnqueueOutcome::OutcomeUnknown(ticket, e) => {
                if !job_id_out.is_null() {
                    unsafe { (*job_id_out).bytes = ticket.job_id };
                }
                set_last_error(&leak_error(e));
                STEADQ_INDETERMINATE
            }
        }
    });
    match result {
        Ok(code) => code,
        Err(_) => {
            set_last_error("panic in steadq_enqueue");
            STEADQ_IO_FAILURE
        }
    }
}
/// Lease the next ready job for `lease_duration_ns` without waiting.
/// Returns STEADQ_OK with a new lease in `*lease_out` (free it with
/// steadq_lease_free). Returns STEADQ_NOT_COMMITTED with `*lease_out` NULL
/// and steadq_last_error() "queue empty" when no job is ready.
/// STEADQ_INDETERMINATE means a job may have been claimed without a usable
/// lease; pass steadq_last_ticket_json() to steadq_resolve.
#[no_mangle]
pub extern "C" fn steadq_lease(
    queue: *mut SteadqQueue,
    lease_duration_ns: u64,
    lease_out: *mut *mut SteadqLease,
) -> c_int {
    clear_last_error();
    clear_last_ticket();
    if queue.is_null() || lease_out.is_null() {
        set_last_error("null queue or lease_out");
        return STEADQ_NOT_COMMITTED;
    }
    unsafe { *lease_out = std::ptr::null_mut() };
    let result = std::panic::catch_unwind(|| {
        let queue = unsafe { &*queue };
        let mut guard = match queue.inner.lock() {
            Ok(guard) => guard,
            Err(_) => {
                set_last_error("queue mutex poisoned");
                return STEADQ_CORRUPTION;
            }
        };
        match guard.lease(0, lease_duration_ns) {
            LeaseOutcome::Leased(lease) => {
                unsafe { *lease_out = Box::into_raw(Box::new(SteadqLease { inner: lease })) };
                STEADQ_OK
            }
            LeaseOutcome::Empty => {
                set_last_error("queue empty");
                STEADQ_NOT_COMMITTED
            }
            LeaseOutcome::NotCommitted(e) => {
                let code = error_to_code(&e);
                set_last_error(&leak_error(e));
                code
            }
            LeaseOutcome::OutcomeUnknown(ticket) => {
                set_last_ticket(&ticket);
                STEADQ_INDETERMINATE
            }
        }
    });
    match result {
        Ok(code) => code,
        Err(_) => {
            set_last_error("panic in steadq_lease");
            STEADQ_IO_FAILURE
        }
    }
}

/// Hash the leased payload and check it against the envelope digest.
/// Returns STEADQ_OK when it matches, STEADQ_CORRUPTION when it does not,
/// or another error code with steadq_last_error(). steadq_ack verifies the
/// payload itself, so this is only needed before acting on the payload
/// without steadq_lease_open_reader.
#[no_mangle]
pub extern "C" fn steadq_lease_verify(queue: *mut SteadqQueue, lease: *mut SteadqLease) -> c_int {
    clear_last_error();
    if queue.is_null() || lease.is_null() {
        set_last_error("null queue or lease");
        return STEADQ_NOT_COMMITTED;
    }
    let result = std::panic::catch_unwind(|| {
        let queue = unsafe { &*queue };
        let guard = match queue.inner.lock() {
            Ok(guard) => guard,
            Err(_) => {
                set_last_error("queue mutex poisoned");
                return STEADQ_CORRUPTION;
            }
        };
        let lease_ref = unsafe { &mut *lease };
        match guard.verify_lease_payload(&lease_ref.inner) {
            Ok(()) => STEADQ_OK,
            Err(e) => {
                let code = error_to_code(&e);
                set_last_error(&leak_error(e));
                code
            }
        }
    });
    match result {
        Ok(code) => code,
        Err(_) => {
            set_last_error("panic in steadq_lease_verify");
            STEADQ_IO_FAILURE
        }
    }
}

/// Extend a lease by `lease_duration_ns` from now. On STEADQ_OK the lease
/// handle is updated in place and must be used for later calls. Returns
/// STEADQ_NOT_COMMITTED with steadq_last_error() "lease lost" when the
/// lease expired or was reaped (stop work on the job: it may run
/// elsewhere). STEADQ_INDETERMINATE means the renewal may or may not have
/// happened; the handle is unchanged, and steadq_last_ticket_json() holds
/// the ticket for steadq_resolve.
#[no_mangle]
pub extern "C" fn steadq_renew(
    queue: *mut SteadqQueue,
    lease: *mut SteadqLease,
    lease_duration_ns: u64,
) -> c_int {
    clear_last_error();
    clear_last_ticket();
    if queue.is_null() || lease.is_null() {
        set_last_error("null queue or lease");
        return STEADQ_NOT_COMMITTED;
    }
    let result = std::panic::catch_unwind(|| {
        let queue = unsafe { &*queue };
        let mut guard = match queue.inner.lock() {
            Ok(guard) => guard,
            Err(_) => {
                set_last_error("queue mutex poisoned");
                return STEADQ_CORRUPTION;
            }
        };
        let lease_ref = unsafe { &mut *lease };
        match guard.renew(&lease_ref.inner, lease_duration_ns) {
            RenewOutcome::Renewed(fresh) | RenewOutcome::Deferred(fresh) => {
                lease_ref.inner = fresh;
                STEADQ_OK
            }
            RenewOutcome::LeaseLost => {
                set_last_error("lease lost");
                STEADQ_NOT_COMMITTED
            }
            RenewOutcome::NotCommitted(e) => {
                let code = error_to_code(&e);
                set_last_error(&leak_error(e));
                code
            }
            RenewOutcome::OutcomeUnknown(ticket) => {
                set_last_ticket(&ticket);
                STEADQ_INDETERMINATE
            }
        }
    });
    match result {
        Ok(code) => code,
        Err(_) => {
            set_last_error("panic in steadq_renew");
            STEADQ_IO_FAILURE
        }
    }
}

/// Acknowledge a leased job: it completes and leaves a receipt. The payload
/// is verified first. Returns STEADQ_OK when acked (also when it was
/// already acked with this lease); STEADQ_NOT_COMMITTED with
/// steadq_last_error() "lease lost" when the lease expired or was reaped;
/// STEADQ_INDETERMINATE when the ack may or may not have happened, with the
/// ticket in steadq_last_ticket_json() for steadq_resolve. The lease handle
/// still needs steadq_lease_free.
#[no_mangle]
pub extern "C" fn steadq_ack(queue: *mut SteadqQueue, lease: *mut SteadqLease) -> c_int {
    clear_last_error();
    clear_last_ticket();
    if queue.is_null() || lease.is_null() {
        set_last_error("null queue or lease");
        return STEADQ_NOT_COMMITTED;
    }
    let result = std::panic::catch_unwind(|| {
        let queue = unsafe { &*queue };
        let mut guard = match queue.inner.lock() {
            Ok(guard) => guard,
            Err(_) => {
                set_last_error("queue mutex poisoned");
                return STEADQ_CORRUPTION;
            }
        };
        let lease_ref = unsafe { &*lease };
        match guard.ack(&lease_ref.inner) {
            steadq_core::AckOutcome::Acked => STEADQ_OK,
            steadq_core::AckOutcome::AlreadyAcked => STEADQ_OK,
            steadq_core::AckOutcome::LeaseLost => {
                set_last_error("lease lost");
                STEADQ_NOT_COMMITTED
            }
            steadq_core::AckOutcome::NotCommitted(e) => {
                let code = error_to_code(&e);
                set_last_error(&leak_error(e));
                code
            }
            steadq_core::AckOutcome::OutcomeUnknown(ticket) => {
                set_last_ticket(&ticket);
                STEADQ_INDETERMINATE
            }
        }
    });
    match result {
        Ok(code) => code,
        Err(_) => {
            set_last_error("panic in steadq_ack");
            STEADQ_IO_FAILURE
        }
    }
}

/// Return a leased job to ready now, consuming the attempt; a job with no
/// attempts left goes to dead instead. Return codes and the lease-lost and
/// ticket contract are as for steadq_ack.
#[no_mangle]
pub extern "C" fn steadq_retry(queue: *mut SteadqQueue, lease: *mut SteadqLease) -> c_int {
    clear_last_error();
    clear_last_ticket();
    if queue.is_null() || lease.is_null() {
        set_last_error("null queue or lease");
        return STEADQ_NOT_COMMITTED;
    }
    let result = std::panic::catch_unwind(|| {
        let queue = unsafe { &*queue };
        let mut guard = match queue.inner.lock() {
            Ok(guard) => guard,
            Err(_) => {
                set_last_error("queue mutex poisoned");
                return STEADQ_CORRUPTION;
            }
        };
        let lease_ref = unsafe { &*lease };
        match guard.retry_now(&lease_ref.inner) {
            TransitionOutcome::Committed => STEADQ_OK,
            TransitionOutcome::LeaseLost => {
                set_last_error("lease lost");
                STEADQ_NOT_COMMITTED
            }
            TransitionOutcome::NotCommitted(e) => {
                let code = error_to_code(&e);
                set_last_error(&leak_error(e));
                code
            }
            TransitionOutcome::OutcomeUnknown(ticket) => {
                set_last_ticket(&ticket);
                STEADQ_INDETERMINATE
            }
        }
    });
    match result {
        Ok(code) => code,
        Err(_) => {
            set_last_error("panic in steadq_retry");
            STEADQ_IO_FAILURE
        }
    }
}

/// Move a leased job to dead with a reason code from spec/reasons.md:
/// 0 unspecified, 1 consumer_rejected, 2 unsupported_content_type,
/// 3 administrative_bury, 4 attempts_exhausted. Any other value returns
/// STEADQ_NOT_COMMITTED without touching the job. Return codes and the
/// lease-lost and ticket contract are as for steadq_ack.
#[no_mangle]
pub extern "C" fn steadq_bury(
    queue: *mut SteadqQueue,
    lease: *mut SteadqLease,
    reason: c_uint,
) -> c_int {
    clear_last_error();
    clear_last_ticket();
    if queue.is_null() || lease.is_null() {
        set_last_error("null queue or lease");
        return STEADQ_NOT_COMMITTED;
    }
    let Some(reason) = u16::try_from(reason)
        .ok()
        .and_then(steadq_core::DeadReason::from_u16)
    else {
        set_last_error(&format!("invalid dead reason {reason}: expected 0-4"));
        return STEADQ_NOT_COMMITTED;
    };
    let result = std::panic::catch_unwind(|| {
        let queue = unsafe { &*queue };
        let mut guard = match queue.inner.lock() {
            Ok(guard) => guard,
            Err(_) => {
                set_last_error("queue mutex poisoned");
                return STEADQ_CORRUPTION;
            }
        };
        let lease_ref = unsafe { &*lease };
        match guard.bury(&lease_ref.inner, reason) {
            TransitionOutcome::Committed => STEADQ_OK,
            TransitionOutcome::LeaseLost => {
                set_last_error("lease lost");
                STEADQ_NOT_COMMITTED
            }
            TransitionOutcome::NotCommitted(e) => {
                let code = error_to_code(&e);
                set_last_error(&leak_error(e));
                code
            }
            TransitionOutcome::OutcomeUnknown(ticket) => {
                set_last_ticket(&ticket);
                STEADQ_INDETERMINATE
            }
        }
    });
    match result {
        Ok(code) => code,
        Err(_) => {
            set_last_error("panic in steadq_bury");
            STEADQ_IO_FAILURE
        }
    }
}

/// Run one recovery pass with the default work budget: reap expired leases,
/// promote due delayed jobs, and compact and expire receipts. Returns
/// STEADQ_OK when the pass had no errors, STEADQ_IO_FAILURE otherwise. A
/// pass that runs out of budget still returns STEADQ_OK; call again to
/// continue.
#[no_mangle]
pub extern "C" fn steadq_recover(queue: *mut SteadqQueue) -> c_int {
    clear_last_error();
    if queue.is_null() {
        set_last_error("null queue");
        return STEADQ_NOT_COMMITTED;
    }
    let result = std::panic::catch_unwind(|| {
        let queue = unsafe { &*queue };
        let mut guard = match queue.inner.lock() {
            Ok(guard) => guard,
            Err(_) => {
                set_last_error("queue mutex poisoned (previous panic during operation)");
                return STEADQ_CORRUPTION;
            }
        };
        let stats = guard.recover(&WorkBudget::default());
        if stats.errors.is_empty() {
            0
        } else {
            1
        }
    });
    match result {
        Ok(0) => STEADQ_OK,
        Ok(_) => {
            set_last_error("recovery completed with errors");
            STEADQ_IO_FAILURE
        }
        Err(_) => {
            set_last_error("panic in steadq_recover");
            STEADQ_IO_FAILURE
        }
    }
}

/// Free a lease handle.
#[no_mangle]
pub extern "C" fn steadq_lease_free(lease: *mut SteadqLease) {
    if !lease.is_null() {
        unsafe { drop(Box::from_raw(lease)) };
    }
}

/// Get the job ID from a lease handle.
#[no_mangle]
pub extern "C" fn steadq_lease_job_id(lease: *const SteadqLease, out: *mut SteadqJobId) {
    if lease.is_null() || out.is_null() {
        return;
    }
    let lease = unsafe { &*lease };
    unsafe { (*out).bytes = lease.inner.job_id };
}

/// Get the generation from a lease handle.
#[no_mangle]
pub extern "C" fn steadq_lease_generation(lease: *const SteadqLease) -> u64 {
    if lease.is_null() {
        return 0;
    }
    unsafe { (*lease).inner.generation }
}

/// Get the attempt from a lease handle.
#[no_mangle]
pub extern "C" fn steadq_lease_attempt(lease: *const SteadqLease) -> c_uint {
    if lease.is_null() {
        return 0;
    }
    unsafe { (*lease).inner.attempt as c_uint }
}

/// Get the payload length from a lease handle.
#[no_mangle]
pub extern "C" fn steadq_lease_payload_length(lease: *const SteadqLease) -> u64 {
    if lease.is_null() {
        return 0;
    }
    unsafe { (*lease).inner.payload_length }
}

/// Copy the boot_id from a lease handle into `out`.
/// Writes a NUL-terminated string. `out_len` is the buffer capacity.
#[no_mangle]
pub extern "C" fn steadq_lease_boot_id(
    lease: *const SteadqLease,
    out: *mut c_char,
    out_len: usize,
) -> c_int {
    if lease.is_null() || out.is_null() || out_len == 0 {
        return STEADQ_NOT_COMMITTED;
    }
    let lease = unsafe { &*lease };
    let boot_id = &lease.inner.boot_id;
    let bytes = boot_id.as_bytes();
    if bytes.len() + 1 > out_len {
        return STEADQ_NOT_COMMITTED;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out as *mut u8, bytes.len());
        *out.add(bytes.len()) = 0; // null terminator
    }
    STEADQ_OK
}

/// Copy the content type from a lease handle into `out`.
/// Writes a NUL-terminated string. `out_len` is the buffer capacity.
#[no_mangle]
pub extern "C" fn steadq_lease_content_type(
    lease: *const SteadqLease,
    out: *mut c_char,
    out_len: usize,
) -> c_int {
    if lease.is_null() || out.is_null() || out_len == 0 {
        return STEADQ_NOT_COMMITTED;
    }
    let lease = unsafe { &*lease };
    let ct = &lease.inner.content_type;
    if ct.len() + 1 > out_len {
        return STEADQ_NOT_COMMITTED;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(ct.as_ptr(), out as *mut u8, ct.len());
        *out.add(ct.len()) = 0;
    }
    STEADQ_OK
}

/// Copy the source path from a lease handle into `out`.
/// Writes a NUL-terminated string. `out_len` is the buffer capacity.
#[no_mangle]
pub extern "C" fn steadq_lease_source_path(
    lease: *const SteadqLease,
    out: *mut c_char,
    out_len: usize,
) -> c_int {
    if lease.is_null() || out.is_null() || out_len == 0 {
        return STEADQ_NOT_COMMITTED;
    }
    let lease = unsafe { &*lease };
    let path = &lease.inner.exact_source_path;
    if path.len() + 1 > out_len {
        return STEADQ_NOT_COMMITTED;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(path.as_ptr(), out as *mut u8, path.len());
        *out.add(path.len()) = 0;
    }
    STEADQ_OK
}

/// Open a verified payload reader for a lease. The payload is hashed once.
/// Returns STEADQ_OK and sets *reader_out on success; the caller must free
/// the reader with steadq_reader_free. Returns STEADQ_NOT_COMMITTED with
/// steadq_last_error() "lease no longer current" when the leased file is
/// gone (the lease was lost), and STEADQ_CORRUPTION when the payload does
/// not match its digest.
#[no_mangle]
pub extern "C" fn steadq_lease_open_reader(
    queue: *mut SteadqQueue,
    lease: *const SteadqLease,
    reader_out: *mut *mut SteadqPayloadReader,
) -> c_int {
    clear_last_error();
    if queue.is_null() || lease.is_null() || reader_out.is_null() {
        set_last_error("null argument");
        return STEADQ_NOT_COMMITTED;
    }
    unsafe { *reader_out = std::ptr::null_mut() };
    let result = std::panic::catch_unwind(|| {
        let steadq = unsafe { &*queue };
        let lease_inner = unsafe { &(*lease).inner };
        let Ok(queue) = steadq.inner.lock() else {
            set_last_error("queue mutex poisoned (previous panic during operation)");
            return STEADQ_CORRUPTION;
        };
        match queue.open_verified_payload_reader(lease_inner) {
            Ok(Some(reader)) => {
                let boxed = Box::new(SteadqPayloadReader { inner: reader });
                unsafe { *reader_out = Box::into_raw(boxed) };
                STEADQ_OK
            }
            Ok(None) => {
                set_last_error("lease no longer current");
                STEADQ_NOT_COMMITTED
            }
            Err(e) => {
                set_last_error(&format!("{e}"));
                error_to_code(&e)
            }
        }
    });
    match result {
        Ok(code) => code,
        Err(_) => {
            set_last_error("panic in steadq_lease_open_reader");
            STEADQ_IO_FAILURE
        }
    }
}

/// Read payload bytes at the given offset.
/// Sets *bytes_read_out to bytes read (0 at EOF).
#[no_mangle]
pub extern "C" fn steadq_reader_read(
    reader: *const SteadqPayloadReader,
    buf: *mut u8,
    buf_len: usize,
    offset: u64,
    bytes_read_out: *mut usize,
) -> c_int {
    clear_last_error();
    if reader.is_null() || buf.is_null() || bytes_read_out.is_null() {
        set_last_error("null argument");
        return STEADQ_NOT_COMMITTED;
    }
    let result = std::panic::catch_unwind(|| {
        let reader = unsafe { &*reader };
        let slice = unsafe { std::slice::from_raw_parts_mut(buf, buf_len) };
        match reader.inner.read_at(slice, offset) {
            Ok(n) => {
                unsafe { *bytes_read_out = n };
                STEADQ_OK
            }
            Err(e) => {
                set_last_error(&format!("{e}"));
                error_to_code(&e)
            }
        }
    });
    match result {
        Ok(code) => code,
        Err(_) => {
            set_last_error("panic in steadq_reader_read");
            STEADQ_IO_FAILURE
        }
    }
}

/// Return the total payload length in bytes.
#[no_mangle]
pub extern "C" fn steadq_reader_payload_len(reader: *const SteadqPayloadReader) -> u64 {
    if reader.is_null() {
        return 0;
    }
    let reader = unsafe { &*reader };
    reader.inner.payload_len()
}

/// Free a payload reader handle.
#[no_mangle]
pub extern "C" fn steadq_reader_free(reader: *mut SteadqPayloadReader) {
    if reader.is_null() {
        return;
    }
    unsafe { drop(Box::from_raw(reader)) };
}

/// Resolve an indeterminate operation from a ticket. The ticket is provided
/// as JSON bytes. If stabilize is non-zero, the resolver attempts to complete
/// any pending barriers. Returns STEADQ_OK on successful resolution.
#[no_mangle]
pub extern "C" fn steadq_resolve(
    queue: *mut SteadqQueue,
    ticket_json: *const u8,
    ticket_len: usize,
    stabilize: c_int,
) -> c_int {
    clear_last_error();
    if queue.is_null() || ticket_json.is_null() || ticket_len == 0 {
        set_last_error("null argument");
        return STEADQ_NOT_COMMITTED;
    }
    // Copy first: the caller may pass the steadq_last_ticket_json buffer.
    let json = unsafe { std::slice::from_raw_parts(ticket_json, ticket_len) }.to_vec();
    let result = std::panic::catch_unwind(|| {
        let steadq = unsafe { &*queue };
        let ticket = match TransitionTicket::from_json(&json) {
            Ok(t) => t,
            Err(e) => {
                set_last_error(&format!("invalid ticket: {e}"));
                return STEADQ_NOT_COMMITTED;
            }
        };
        let Ok(queue) = steadq.inner.lock() else {
            set_last_error("queue mutex poisoned (previous panic during operation)");
            return STEADQ_CORRUPTION;
        };
        match queue.resolve(&ticket, stabilize != 0) {
            ResolutionOutcome::SourceObserved
            | ResolutionOutcome::SourceStabilized
            | ResolutionOutcome::DestinationObserved
            | ResolutionOutcome::DestinationStabilized => STEADQ_OK,
            ResolutionOutcome::BothObserved => STEADQ_CORRUPTION,
            ResolutionOutcome::NeitherObserved => STEADQ_NOT_COMMITTED,
            ResolutionOutcome::ConflictingObject => STEADQ_CORRUPTION,
            ResolutionOutcome::ResolutionFailed(e) => {
                set_last_error(&format!("{e}"));
                error_to_code(&e)
            }
        }
    });
    match result {
        Ok(code) => code,
        Err(_) => {
            set_last_error("panic in steadq_resolve");
            STEADQ_IO_FAILURE
        }
    }
}

/// Format an error for the thread-local last-error store.
fn leak_error(e: Error) -> String {
    format!("{e}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_ticket_survives_resolve_and_clears_on_the_next_lease() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = CString::new(dir.path().to_str().unwrap()).unwrap();
        let queue = steadq_init(path.as_ptr(), 1);
        assert!(!queue.is_null());

        store_last_ticket(b"{}".to_vec());
        let ticket = steadq_last_ticket_json();
        assert!(!ticket.is_null());
        let len = unsafe { std::ffi::CStr::from_ptr(ticket) }.to_bytes().len();
        assert_eq!(
            steadq_resolve(queue, ticket.cast(), len, 0),
            STEADQ_NOT_COMMITTED
        );
        let error = unsafe { std::ffi::CStr::from_ptr(steadq_last_error()) };
        assert!(error.to_str().unwrap().starts_with("invalid ticket"));
        assert_eq!(steadq_last_ticket_json(), ticket);
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(ticket) }.to_bytes(),
            b"{}"
        );

        let mut lease = std::ptr::null_mut();
        assert_eq!(
            steadq_lease(queue, 1_000_000_000, &mut lease),
            STEADQ_NOT_COMMITTED
        );
        assert!(lease.is_null());
        assert!(steadq_last_ticket_json().is_null());
        assert_eq!(last_error(), "queue empty");
        steadq_close(queue);
    }

    fn last_error() -> String {
        let error = steadq_last_error();
        assert!(!error.is_null());
        unsafe { CStr::from_ptr(error) }
            .to_string_lossy()
            .into_owned()
    }

    /// Enqueue one job and lease it.
    fn leased_queue(dir: &std::path::Path) -> (*mut SteadqQueue, *mut SteadqLease) {
        let path = CString::new(dir.as_os_str().as_bytes()).unwrap();
        let queue = steadq_init(path.as_ptr(), 1);
        assert!(!queue.is_null());
        let mut id = SteadqJobId { bytes: [0; 16] };
        let payload = b"job";
        assert_eq!(
            steadq_enqueue(
                queue,
                payload.as_ptr(),
                payload.len(),
                ptr::null(),
                3,
                &mut id
            ),
            STEADQ_OK
        );
        let mut lease = ptr::null_mut();
        assert_eq!(steadq_lease(queue, 30_000_000_000, &mut lease), STEADQ_OK);
        (queue, lease)
    }

    #[test]
    fn bury_rejects_reasons_outside_the_registry() {
        let dir = tempfile::TempDir::new().unwrap();
        let (queue, lease) = leased_queue(dir.path());
        for reason in [5, 0x1_0001] {
            assert_eq!(steadq_bury(queue, lease, reason), STEADQ_NOT_COMMITTED);
            assert!(last_error().starts_with("invalid dead reason"));
        }
        assert_eq!(steadq_bury(queue, lease, 1), STEADQ_OK);
        steadq_lease_free(lease);
        steadq_close(queue);
    }

    #[test]
    fn renew_updates_the_lease_in_place_and_reader_reports_lost_lease() {
        let dir = tempfile::TempDir::new().unwrap();
        let (queue, lease) = leased_queue(dir.path());
        let before = unsafe { (*lease).inner.expires_boottime_ns };
        assert_eq!(steadq_renew(queue, lease, 60_000_000_000), STEADQ_OK);
        assert!(unsafe { (*lease).inner.expires_boottime_ns } > before);
        // The renewed handle acks; the stale path is gone for readers.
        let stale = SteadqLease {
            inner: unsafe { (*lease).inner.clone() },
        };
        assert_eq!(steadq_ack(queue, lease), STEADQ_OK);
        let mut reader = ptr::null_mut();
        assert_eq!(
            steadq_lease_open_reader(queue, &stale, &mut reader),
            STEADQ_NOT_COMMITTED
        );
        assert!(reader.is_null());
        assert_eq!(last_error(), "lease no longer current");
        assert_eq!(
            steadq_renew(queue, lease, 1_000_000_000),
            STEADQ_NOT_COMMITTED
        );
        assert_eq!(last_error(), "lease lost");
        steadq_lease_free(lease);
        steadq_close(queue);
    }

    #[test]
    fn init_and_open_accept_non_utf8_paths() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut bytes = dir.path().as_os_str().as_bytes().to_vec();
        bytes.extend_from_slice(b"/q\xff");
        let path = CString::new(bytes).unwrap();
        let queue = steadq_init(path.as_ptr(), 1);
        if queue.is_null() {
            // The bytes reached the filesystem; a utf8only filesystem (ZFS)
            // refuses the name with EILSEQ.
            assert!(last_error().contains("os error 84"), "{}", last_error());
            return;
        }
        steadq_close(queue);
        let queue = steadq_open(path.as_ptr());
        assert!(!queue.is_null(), "{}", last_error());
        steadq_close(queue);
    }

    #[test]
    fn init_failure_names_the_class_and_the_system_error() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("file");
        std::fs::write(&file, b"x").unwrap();
        let path = CString::new(file.join("q").as_os_str().as_bytes()).unwrap();
        assert!(steadq_init(path.as_ptr(), 1).is_null());
        let error = last_error();
        assert!(error.contains(": "), "{error}");
    }

    #[test]
    fn init_error_mapping_preserves_kind() {
        for kind in [
            std::io::ErrorKind::StorageFull,
            std::io::ErrorKind::QuotaExceeded,
        ] {
            assert_eq!(
                classify_init_error(std::io::Error::from(kind)),
                Error::ResourceExhausted
            );
        }
        for kind in [
            std::io::ErrorKind::InvalidInput,
            std::io::ErrorKind::InvalidData,
            std::io::ErrorKind::AlreadyExists,
        ] {
            assert!(matches!(
                classify_init_error(std::io::Error::from(kind)),
                Error::InvalidInput(_)
            ));
        }
        assert!(matches!(
            classify_init_error(std::io::Error::new(std::io::ErrorKind::Unsupported, "fs")),
            Error::UnsupportedFilesystem
        ));
        assert!(matches!(
            classify_init_error(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "perm"
            )),
            Error::PermissionDenied
        ));
        assert!(matches!(
            classify_init_error(std::io::Error::new(std::io::ErrorKind::WouldBlock, "lock")),
            Error::MaintenanceBusy
        ));
        assert!(matches!(
            classify_init_error(std::io::Error::other("io")),
            Error::IoFailure(_)
        ));
    }
}
