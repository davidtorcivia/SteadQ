# Crash lab

Reproducible storage-crash testing for SteadQ queue directories.

The crash lab records every block write issued by a workload on a real
filesystem, replays the log up to each persistence barrier (fsync, FUA),
and verifies each resulting on-disk state against the queue contract.

Three lanes:

- **tier0** (no root required): SIGKILL lane. A workload process is killed
  after a target number of completed operations; the surviving operation
  prefix defines the expectations. Process-crash evidence only.
- **tier1** (root required): dm-log-writes lane. Every crash state at every
  persistence barrier is mounted and checked. Exhaustive over crash states
  reachable at persistence boundaries, for the recorded workload.
- **flakey** (root required): dm-flakey power-cut lane. A multi-threaded
  workload runs on ext4 over a dm-flakey target; at a random point every
  later write is dropped (or failed), the workload is killed, and the
  remounted filesystem is checked. Sampled, not exhaustive, but it reaches
  live concurrent kernel states that a single recorded write log does not.

## Gates

Each crash state must satisfy:

- No committed enqueue is lost.
- No acknowledged or buried job is active.
- No phantom job is delivered.
- No enqueue that returned NotCommitted is visible.
- No job is in more than one state.
- Recovery completes without errors.
- fsck reports no error-severity findings.
- Corrupt payloads are quarantined, never delivered.

## Usage

```sh
cargo xtask crashlab doctor                 # tool and device preflight
cargo xtask crashlab tier0 --runs 24        # SIGKILL lane
sudo cargo xtask crashlab tier1 --fs ext4   # also xfs, btrfs, f2fs, zfs
sudo target/debug/xtask crashlab flakey --cuts 200   # dm-flakey power cuts
cargo xtask crashlab teardown               # release resources after an interrupted run
```

Tier 1 requires `replay-log` from xfstests (`src/log-writes/`), `mkfs.<fs>`,
`losetup`, `dmsetup`, and the `dm-log-writes` kernel module. The ZFS
profile additionally requires `zpool`/`zfs` and creates its pool on the
log device, so pool creation is itself crash-tested; crash states are
recovered by force-importing the run's pool from exactly the run's loop
device (never a bare `zpool import`, which scans every host device), and
states that predate pool creation are vacuous passes. Pools use
`cachefile=none` so runs never touch the host pool cache.

## Power-cut lane (dm-flakey)

Run it on a disposable root VM, never in PR CI. It needs `losetup`,
`dmsetup`, `mkfs.ext4`, and the `dm-flakey` module (`modprobe dm-flakey`).
Build as the normal user first so root finds the binaries and leaves no
root-owned build output, then run the xtask binary under sudo:

```sh
cargo build -p steadq-testkit --bins -p xtask
sudo target/debug/xtask crashlab flakey --cuts 200 --seed 1
sudo target/debug/xtask crashlab flakey --cuts 100 --mount-opts data=journal
sudo target/debug/xtask crashlab flakey --cuts 100 --mode error_writes
```

Flags: `--cuts N` cut points (default 20), `--seed N`, `--workers N`
(default 4, at least 3), `--mode drop_writes|error_writes`, `--mount-opts`
(passed to `mount -o`), `--min-ops`/`--max-ops` (the cut lands after a
uniformly chosen number of completed operations, default 20 to 2000),
`--size-mb` (image size, default 1024), `--store DIR`.

Each cut point:

1. `mkfs.ext4` (default options) on a loop device over an image in the
   store, then a dm-flakey table that passes every write, and mount.
2. Start `crashlab-concurrent`: worker 0 enqueues with `deferred_dir_sync`
   and calls `sync()`, worker 1 runs group-commit batches (enqueue batch,
   then lease and ack batch), and the rest run strict enqueue, lease (some
   with 1 s leases so recovery reaps them), ack, retry, bury, and bounded
   recovery. Every returned outcome, including the job id of a
   NotCommitted enqueue, is appended to an op log in the store, off the
   tested device. Deferred and batched enqueues and batched acks are logged
   as committed only after their `sync()` or `commit()` returns.
3. After the chosen number of op-log lines, append a cut marker to the op
   log, then `dmsetup suspend --nolockfs`, load the `drop_writes` (or
   `error_writes`) table, and resume. No freeze, so nothing is flushed on
   the way into the cut. The workload keeps running 100 to 300 ms against
   the lying device, then gets SIGKILL.
4. Unmount, remove the dm device (dropping its page cache), recreate it with
   the pass-through table, and mount (journal replay).
5. `crashlab-check` recovers to quiescence, runs deep fsck, and applies the
   gates. Lines before the marker returned before any write was dropped, so
   they set the durability expectations; lines after it set none, except
   that a NotCommitted enqueue must stay invisible whenever it returned.

The first failing cut stops the run and keeps the op log, verdict, and a
copy of the image in the store. The run summary records the kernel, mode,
mount options, and how many operations of each type returned after the
cut.

The model: writes that reached the loop device before the switch survive
and later writes vanish, which is what a power cut does to data that was
never flushed. It does not reorder writes inside the device; tier 1 covers
every persistence-barrier prefix of a recorded log.

A negative control (logging `acked` before calling `ack`) failed at the
12th cut with the acked job still leased, so the gates catch a violated
durability promise.

## Device safety

The crash lab never writes to the OS drive or to any device holding other
data. Block targets are restricted to loop devices created by the tooling
itself, backed by image files under allowlisted scratch directories
(`/dev/shm/crashlab`, `target/crashlab`, or the path in `$CRASHLAB_STORE`).

Guards, enforced on every operation:

- Backing files resolve under an allowlisted store; traversal and symlink
  escape are rejected.
- The target must be a loop device attached to the run's own backing file
  (verified via `losetup`), with exact device-name matching.
- Whole-disk, partition, device-mapper, and md nodes are refused.
- Devices that are the source (or parent) of a mounted filesystem are refused.
- Device-mapper tables and mount points are namespaced per run and recorded
  in a registry; `teardown` releases a crashed run's resources.
- ZFS pools are created and imported scoped to the run's own loop device
  and pool name only; the host pool cache is never written.

## Output

Each tier 1 run writes a manifest recording the kernel, mkfs and mount
options, seed, entry and barrier counts, and one verdict per checked crash
state. The first failing state stops the run and preserves the images for
reproduction.

## Results

Block-replay coverage per profile for a 40-operation workload, seed 1
(loop-backed images, dm-log-writes replay at every persistence barrier).

First host, kernel 6.8.0-137-generic (761 states):

| Filesystem | mkfs | States checked | Result |
|---|---|---:|---|
| ext4 | mke2fs 1.47.0 | 198 | all passed |
| XFS | mkfs.xfs 6.6.0 | 161 | all passed |
| btrfs | btrfs-progs 6.6.3 | 157 | all passed |
| f2fs | mkfs.f2fs 1.16.0 | 144 | all passed |
| ZFS | zfs 2.2.2 (pool creation and force-import recovery) | 101 | all passed |

Independent host `nyx` (IceWhale ZimaBoard2, Intel N150), kernel
7.0.0-28-generic (793 states):

| Filesystem | mkfs | States checked | Result |
|---|---|---:|---|
| ext4 | mke2fs 1.47.0 | 217 | all passed |
| XFS | mkfs.xfs 6.6.0 | 144 | all passed |
| btrfs | btrfs-progs 6.6.3 | 187 | all passed |
| f2fs | mkfs.f2fs 1.16.0 | 149 | all passed |
| ZFS | zfs 2.2.2-0ubuntu9.4 userspace, kmod 2.4.1-1ubuntu5 (pool creation and force-import recovery) | 96 | all passed |

State counts differ by kernel because the recorded write log has a
different barrier set. They are not the same 761 states replayed twice.

On `nyx`, a separate live-queue check on the host btrfs RAID1 volume
put 15 jobs, SIGKILL'd a leasing consumer that left one in-flight lease,
reaped that lease after expiry, and drained the rest. Final stats:
15 receipts, 0 ready, 0 leased, 0 dead, 0 quarantine. That is process-crash
evidence on real storage, not a tier1 replay.

Tier 0 (SIGKILL): 84 runs across five seeds on the first host, all passed.

Power-cut lane (dm-flakey), boat.dev KVM VMs (4 vCPU, 8 GB), kernel
6.8.0-117-generic, mke2fs 1.47.0 default options, 1 GiB image in
`/dev/shm`, 1,350 cut points, all passed:

| Mode | Mount options | Workers | Ops before cut | Cuts | Result |
|---|---|---:|---|---:|---|
| drop_writes | default | 4 | 20 to 3,000 | 200 | all passed |
| drop_writes | default | 4 | 3,000 to 20,000 | 100 | all passed |
| drop_writes | default | 8 | 20 to 5,000 | 200 | all passed |
| drop_writes | default | 3 | 20 to 3,000 | 100 | all passed |
| drop_writes | default | 12 | 20 to 8,000 | 150 | all passed |
| drop_writes | data=journal | 4 | 20 to 3,000 | 200 | all passed |
| drop_writes | data=journal | 4 | 3,000 to 15,000 | 100 | all passed |
| error_writes | default | 4 | 20 to 3,000 | 200 | all passed |
| error_writes | data=journal | 4 | 20 to 3,000 | 100 | all passed |

Under drop_writes about 2,000 to 2,700 operations per cut returned after
the switch (every type: enqueue, deferred sync, lease, ack, retry, bury,
recovery) and set no expectation. Under error_writes the post-cut
operations failed fast, and no enqueue that returned NotCommitted was
visible after remount.

Scope: one workload shape and seed per profile, two kernels, no hardware
power-cut testing, no second-crash-after-resolution lane. State verdicts
gate on durable obligations only: damage to objects whose completion is
not in the durable operation prefix is recorded, not failed.
