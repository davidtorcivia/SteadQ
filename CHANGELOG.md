# Changelog

## Unreleased

### Features

- `steadq work PATH -- COMMAND` leases jobs, streams each payload to the command's stdin, renews the lease at half its duration, acks on exit 0, and requeues on nonzero; `--concurrency N` runs N workers, `--once` runs one job and exits with its code for cron glue. A payload read failure requeues instead of acking a truncated delivery
- `steadq fsck PATH [--deep] [--repair]` re-verifies name tags, digests, and shard placement, hashes payloads with `--deep`, and quarantines corrupt objects with `--repair`; exit is 3 whenever an Error-severity finding exists, including after repair
- Renewals defer their directory barrier under `deferred_dir_sync`, returning `RenewOutcome::Deferred` with current lease info; `sync()` flushes accumulated barriers for workers renewing many leases, an ack makes the renewal durable through its own barriers, and a crash before sync simply expires the lease (at-least-once). `steadq work` opens with deferred sync so each renewal is a rename with no fsync
- The bounded lease wait wakes on ready-shard inotify events (`IN_CREATE` for linkat publication, `IN_MOVED_TO` for rename publication and delayed promotion); the scan remains the sole source of truth, the backoff schedule is unchanged, and any watch failure degrades the handle permanently to plain sleeps. Idle dispatch latency on the measurement host drops from the 10 ms backoff ceiling to a 377 µs median
- `steadq stats --prometheus` emits per-state `steadq_<state>_objects` and `steadq_<state>_oldest_age_seconds` gauges; plain and `--json` stats outputs gain oldest-object age. The oldest age is the global minimum across subtrees, and an unreadable state directory exits with the io code instead of reporting zero objects

### Documentation

- `docs/name-grammar-policy.md` states how the 59-byte filename headroom may be spent: fields append with fixed widths and unused prefix letters, the name-tag context version and FORMAT minor bump together with any grammar revision, and old readers treat unrecognized names as inert warnings rather than corruption (the version-gating and warning-class findings are required companion changes for any revision, named in the policy)
- The contract gains a disk-full classification section: storage exhaustion before linearization is NotCommitted (resource exhausted), after linearization it is OutcomeUnknown, orphaned `tmp/` files are never delivered and are swept by the recovery retention pass, and handle poisoning or quarantine never results from `ENOSPC` or `EDQUOT`

### Structure

- `steadq_fs_linux::fault::pin_clock_realtime_ns` freezes the realtime clock for the life of a test thread, and `fault::reset()` restores the pin instead of the wall clock. The shared test queue fixtures and the deferred-sync tests that build a queue inline pin before `Queue::init`, so a 10-second delayed-bucket boundary can no longer trigger a wall-watermark advance mid-test; that advance consumed count-based `fsync_dir_fd` faults before the operation under test reached them and made `claim_move_records_each_directory_barrier` fail on CI
- Supported targets are now 64-bit x86_64 or aarch64 Linux with the gnu or musl environment; CI cross-checks `aarch64-unknown-linux-gnu` and `x86_64-unknown-linux-musl` and still rejects 32-bit and out-of-set targets. `x86_64-unknown-linux-gnu` remains the certified release target

- Claim keeps the leased file in `ready/<shard>/`. The leased filename includes boot id (`.o` + 32 hex). Recovery still walks `leased/` for the previous layout and reaps colocated leased names from `ready/`
- README test count matches `cargo test --workspace --all-features -- --list` (706)
- Removed leftover `dead_code`/`unused_imports` allows on live items and the unused power-loss `is_durable` helper
- Split `queue/mod.rs` into publish, lease, consumer, and inspect modules; init and open stay in the parent
- Split recovery phases into reap, promote, and retain
- Deleted the `ensure_dir_pub` wrapper and the always-true tag self-comparison in `validate_active_object`

### Fixes

- Storage exhaustion (`ENOSPC`, `EDQUOT`) before linearization now reports `ResourceExhausted` on ack, retry, renew, bury, dead removal, and the dead-letter move that claim performs on attempt exhaustion, matching the contract's disk-full classification; these consumer transitions previously returned `IoFailure` with the errno inside the message, so the CLI exited 6 instead of 4 and the C ABI returned `STEADQ_IO_FAILURE` instead of `STEADQ_RESOURCE_EXHAUSTED`. One `From<io::Error>` classifier replaces the per-site `IoFailure(e.to_string())` conversions in `steadq-core`. The claim-time dead-letter move and the wall-watermark advance no longer poison the handle on `ResourceExhausted`; both previously poisoned on every error. Post-linearization failures in those paths keep the `IoFailure` classification and still poison. A failed watermark advance now unlinks its `control/.wm.adv.*` temp file instead of orphaning it
- Deleted the unused `MoveActor` parameter from the transition engine and the unused `steadq-fs-linux` helpers `durable_move_noreplace`, `durable_move_replace`, `syncfs`, `read_dir_for_each`, `is_resource_exhausted`, `is_sync_failure`, `is_capability_error`, and `should_propagate_on_fallback`
- The first `ensure_dir` of a shard leaf creates every sibling shard and `fsync`s the bucket once, matching how init fills `ready/`
- Streaming tmpfile enqueue no longer fsyncs the destination directory after `publish_tmpfile_noreplace_with_mode`, which already synced it
- Receipt compaction and retention record open and lock I/O instead of treating those failures as a busy skip
- Deleted unused public name helpers `name_tag_hex`, `filename_without_tag_and_ext`, and `verify_ready_tag`
- Production identity changes (generation and attempt) come from the protocol IR via `next_common_fields`
- Streaming enqueue records deferred dirty directories and skips dest-dir fsync until `sync()`, matching buffered enqueue
- CLI maps every command through the spec 11.5 exit table (`exit_core` / `exit_io`) instead of collapsing most failures to 1
- CLI lease handles persist payload length, digest, and content type so `ack`/`retry`/`bury` work after `lease --handle-file`
- `steadq doctor` accepts ZFS and the alternate f2fs statfs magic, and honors the global `--json` flag
- Streaming enqueue fails closed when `getrandom` fails instead of publishing job id `0`
- Admin dead export/remove reject invalid job IDs instead of operating on the all-zero id
- CBOR metadata encodes `i64::MIN` without overflowing
- C `steadq_init` maps unsupported filesystem and permission errors to the matching result codes
- C resolve reports `BothObserved` as corruption, matching the CLI
- Batch/deferred lease records dirty directories only after a successful claim rename, and a record failure is OutcomeUnknown
- Streaming enqueue keeps the published envelope digest on OutcomeUnknown
- Lease scan stops after a failed exhausted-attempt dead-letter move instead of claiming on a poisoned handle
- Claim of a corrupt payload that cannot be quarantined is OutcomeUnknown, not NotCommitted
- `renew` returns NotCommitted instead of panicking when lease-bucket arithmetic is exhausted
- Recovery quarantines malformed leased filenames instead of skipping them

### Performance

- Re-measured completed-job throughput on the README Intel ext4 NVMe after same-directory lease: strict 2,679/s, deferred sync-every-job 3,463/s, deferred batch-10 3,229/s, deferred batch-50 3,453/s. Concurrent 64 B is 2,816/5,633/8,177 jobs/s at 1/4/8 threads. A warm job that does not advance the watermark issues 6 `fsync`; lease still dest-syncs and source-syncs the ready shard.

### Core

- Full queue lifecycle: init, open, enqueue, lease, ack, retry, bury, renew, recover, inspect
- Streaming enqueue (accepts any `std::io::Read` without buffering the full payload)
- Verified payload reader (hashes payload once, serves O(1) random-access reads)
- All state transitions route through a single phase-aware executor
- Payload integrity verified by SHA-256 at every transition
- Wall clock watermark prevents early delivery after clock rollback
- Bounded, resumable recovery with directory-entry durability

### C ABI

- Opaque queue, lease, and payload reader handles
- Full lifecycle: init, open, enqueue, lease, verify, ack, retry, bury, recover, resolve
- Payload streaming via verified reader
- Ticket-based resolution of indeterminate operations
- Generated header via cbindgen with CI drift check

### Testing

- 706 tests: unit, fault injection, differential, and formal model checking
- Stateful differential driver verifies production API against logical oracle
- Six TLA+ model configurations with drift-checked generated metadata
- Diff-scoped mutation testing on every pull request
- Tests that require non-UTF-8 directory names or link publication skip on filesystems that reject those inputs (ZFS utf8only, strict ext4 encoding)

### Infrastructure

- Closed protocol IR with versioned schema and typed domains
- Reproducible toolchain pinning (Rust 1.97.1, x86_64-unknown-linux-gnu)
- Compatibility policy for independent versioning of disk format, Rust API, C ABI, and ticket schema
- Crash lab (`cargo xtask crashlab`): SIGKILL lane and dm-log-writes replay lane with device-safety guards, run registry, and per-state manifests (docs/crash-lab.md)
- Crash replay passes for all five profiles on two hosts: 761 states on kernel 6.8.0-137 and 793 states on kernel 7.0.0-28 (nyx), all passing
- ZFS supported: named-fallback publication, pool force-import crash recovery, and both f2fs statfs magic constants accepted
