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

- `MoveFailureWith<E>`, generic over an error type that was always `io::Error`, and its identity mapper closures are gone; `move_noreplace` returns `MoveFailure` and the publish path has one `from_move_failure` classifier instead of three. The post-claim structural checks in the lease loop are one `validate_claimed_object` call instead of ten inline poison-and-return blocks
- `steadq_fs_linux::fault::pin_clock_realtime_ns` freezes the realtime clock for the life of a test thread, and `fault::reset()` restores the pin instead of the wall clock. The shared test queue fixtures and the deferred-sync tests that build a queue inline pin before `Queue::init`, so a 10-second delayed-bucket boundary can no longer trigger a wall-watermark advance mid-test; that advance consumed count-based `fsync_dir_fd` faults before the operation under test reached them and made `claim_move_records_each_directory_barrier` fail on CI
- The CLI `main` is a dispatcher: each command body moved verbatim into a `cmd_*` function, `open_or_exit` and `parse_hex_id` replace the per-arm open and id parsing, and `atomic_write_private` replaces the two copies of the temp-write-rename sequence behind `--handle-file` and `--ticket-out`
- `steadq verify` and `steadq format-dump` share `describe_record`, which validates job envelopes through `steadq_format::ValidatedEnvelope` and also decodes receipt and watermark records; `verify` reports the same fields `format-dump` prints
- `steadq-names` decodes every fixed-width hex field through one const-generic `hex_decode_array`, and the four tagged-field parsers share `strip_tag`
- `crashlab-check` splits `run_check` into `DurablePrefix`, `recover_to_quiescence`, `fsck_gate`, `check_prefix_jobs`, and `probe_deliveries`; the JSON verdict is unchanged
- Supported targets are now 64-bit x86_64 or aarch64 Linux with the gnu or musl environment; CI cross-checks `aarch64-unknown-linux-gnu` and `x86_64-unknown-linux-musl` and still rejects 32-bit and out-of-set targets. `x86_64-unknown-linux-gnu` remains the certified release target

- Claim keeps the leased file in `ready/<shard>/`. The leased filename includes boot id (`.o` + 32 hex). Recovery still walks `leased/` for the previous layout and reaps colocated leased names from `ready/`
- README test count matches `cargo test --workspace --all-features -- --list` (706)
- Removed leftover `dead_code`/`unused_imports` allows on live items and the unused power-loss `is_durable` helper
- Split `queue/mod.rs` into publish, lease, consumer, and inspect modules; init and open stay in the parent
- Split recovery phases into reap, promote, and retain
- Deleted the `ensure_dir_pub` wrapper and the always-true tag self-comparison in `validate_active_object`

### Fixes

- `steadq fsck` reports a directory it cannot open or list as an Error-severity `directory_scan_incomplete` finding instead of silently skipping the subtree and reporting the queue clean; one depth-driven walker replaces the separate state and leased walkers. A bucket or shard that a concurrent retention pass removed between the listing and the open is skipped without a finding. An object file above its shard level is verified and fails closed as before; a `.rct` inside a legacy `leased/` shard, previously a warning, is now verified the same way
- `list_quarantine`, `remove_quarantine`, and `export_quarantine` are fd-relative with `O_NOFOLLOW` like the rest of the crate; a symlink planted under `quarantine/` is listed but never followed, so remove unlinks the link and export fails
- Recovery quarantines a delayed or receipt object whose filename does not parse, the policy the lease reaper already applied; promotion previously skipped such names silently every pass and retention only recorded them
- Promotion blocks its phase with `promote_wall_bucket` when the wall floor has no delayed bucket instead of returning silently; the bucket is computed once per pass
- The colocated-lease reap scan persists the ready shard it stopped at (`reap_colocated_shard` in the recovery cursor, defaulted when absent and omitted when unset, so a cursor persisted after the colocated scan completes stays readable by the previous release; one persisted mid-scan after budget exhaustion is not, and the previous release then refuses to open the queue until `control/recovery-cursor.json` is removed) and resumes there on the next pass, and records a shard it cannot open as `reap_shard_open`
- `Queue::list_dead` walks `dead/` fd-relative, authenticates each name tag, and errors on an unreadable directory; `steadq admin dead-list` prints job id, generation, attempts, and path through it instead of raw filenames from a path walk
- The recovery movers (`reap_to_ready`, `reap_to_dead`, `promote_to_ready`, and the colocated pair) take the caller's open shard fd instead of re-resolving the source directory from the root; the public `compact_receipts` wrapper that bypassed the recovery lock and cursor is gone
- fsck deep verification hashes payloads through the shared `verify_payload`, so a bound tightened in the verifier applies to fsck too
- A poisoned handle records why (`PoisonReason`: post-linearization state unknown, wall watermark authority lost, or internal invariant violation), keeps the first reason, exposes it through `Queue::poison_reason`, and names it in the `QueuePoisoned` message. The claim-time dead-letter move no longer poisons on a failure before its rename; it reports the classified error (`StateExhausted` and `InvalidInput` from identity arithmetic survive as themselves) and leaves the handle usable; a collision at the dead path still poisons as an invariant violation, and only a failure past the rename poisons with the post-linearization reason. The pre-ack payload re-verification poisons only on `PayloadCorrupt` or `QueueCorrupt`; a transient read failure there returns `IoFailure` with the handle usable. The `QueuePoisoned` message is the reason alone
- Storage exhaustion (`ENOSPC`, `EDQUOT`) before linearization now reports `ResourceExhausted` on ack, retry, renew, bury, dead removal, and the dead-letter move that claim performs on attempt exhaustion, matching the contract's disk-full classification; these consumer transitions previously returned `IoFailure` with the errno inside the message, so the CLI exited 6 instead of 4 and the C ABI returned `STEADQ_IO_FAILURE` instead of `STEADQ_RESOURCE_EXHAUSTED`. One `From<io::Error>` classifier replaces the per-site `IoFailure(e.to_string())` conversions in `steadq-core`. The claim-time dead-letter move and the wall-watermark advance no longer poison the handle on `ResourceExhausted`; both previously poisoned on every error. Post-linearization failures in those paths keep the `IoFailure` classification and still poison. A failed watermark advance now unlinks its `control/.wm.adv.*` temp file instead of orphaning it
- Deleted the unused `MoveActor` parameter from the transition engine and the unused `steadq-fs-linux` helpers `durable_move_noreplace`, `durable_move_replace`, `syncfs`, `read_dir_for_each`, `is_resource_exhausted`, `is_sync_failure`, `is_capability_error`, and `should_propagate_on_fallback`
- The three C ABI functions that did not catch panics (`steadq_lease_open_reader`, `steadq_reader_read`, `steadq_resolve`) now do, and clear the last error before their argument checks like every other export. `steadq_last_ticket_json` returns the transition ticket after an indeterminate lease, ack, retry, or bury so C callers can reach `steadq_resolve`; the buffer stays valid until the next enqueue, lease, ack, retry, or bury on the same thread, and `steadq_resolve` copies its input before touching any thread-local slot
- `steadq admin` commands print the open or operation failure and exit through the spec exit table instead of a silent exit 6; `steadq resolve` maps a read failure through `exit_io` and a resolution failure through `exit_core`; `steadq bench` reports a worker open failure instead of panicking and rejects a lease duration that overflows nanoseconds
- `make_leased_name` returns `None` for a non-canonical boot id instead of a name built from sixteen zero bytes; `Layout::leased_for_boot` reports `InvalidTicket`
- The testkit `Rng` maps seed 0 to 1, since xorshift has a fixed point at zero
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
