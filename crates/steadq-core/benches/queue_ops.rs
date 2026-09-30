use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use steadq_core::{
    AckOutcome, CreateOptions, EnqueueInput, EnqueueOutcome, Error, LeaseInfo, LeaseOutcome,
    OpenOptions, Queue,
};
use tempfile::TempDir;

const MAX_CONTENTION_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

fn benchmark_tempdir() -> TempDir {
    match std::env::var_os("STEADQ_BENCH_ROOT") {
        Some(root) => TempDir::new_in(root).unwrap(),
        None => TempDir::new().unwrap(),
    }
}

fn enqueue_one(queue: &mut Queue, payload: &[u8]) {
    let started = std::time::Instant::now();
    loop {
        match queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: payload.to_vec(),
            ..Default::default()
        }) {
            EnqueueOutcome::Committed(_) => return,
            EnqueueOutcome::NotCommitted(_, Error::MaintenanceBusy) => {
                pause_for_contention(started, "enqueue");
            }
            outcome => panic!("enqueue failed: {outcome:?}"),
        }
    }
}

fn lease_one(queue: &mut Queue) -> LeaseInfo {
    let started = std::time::Instant::now();
    loop {
        match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(lease) => return lease,
            LeaseOutcome::Empty | LeaseOutcome::NotCommitted(Error::MaintenanceBusy) => {
                pause_for_contention(started, "lease");
            }
            outcome => panic!("lease failed: {outcome:?}"),
        }
    }
}

fn ack_one(queue: &mut Queue, lease: &LeaseInfo) {
    let started = std::time::Instant::now();
    loop {
        match queue.ack(lease) {
            AckOutcome::Acked => return,
            AckOutcome::NotCommitted(Error::MaintenanceBusy) => {
                pause_for_contention(started, "ack")
            }
            outcome => panic!("ack failed: {outcome:?}"),
        }
    }
}

fn pause_for_contention(started: std::time::Instant, operation: &str) {
    assert!(
        started.elapsed() < MAX_CONTENTION_WAIT,
        "{operation} remained contended for {MAX_CONTENTION_WAIT:?}"
    );
    std::thread::yield_now();
}

fn bench_enqueue(c: &mut Criterion) {
    let mut group = c.benchmark_group("enqueue");
    for payload_size in [64usize, 1024, 16384, 65536].iter() {
        group.throughput(criterion::Throughput::Bytes(*payload_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(payload_size),
            payload_size,
            |b, &size| {
                b.iter_batched(
                    || {
                        let tmp = benchmark_tempdir();
                        Queue::init(tmp.path(), &CreateOptions::default()).unwrap();
                        let q = Queue::open(
                            tmp.path(),
                            &OpenOptions {
                                allow_unsupported_fs: true,
                                ..Default::default()
                            },
                        )
                        .unwrap();
                        (tmp, q)
                    },
                    |(_tmp, mut q)| {
                        let payload = vec![0xABu8; size];
                        let outcome = q.enqueue(EnqueueInput {
                            maximum_attempts: 3,
                            content_type: "x".to_string(),
                            payload,
                            ..Default::default()
                        });
                        assert!(matches!(outcome, EnqueueOutcome::Committed(_)));
                        black_box(outcome);
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_fsck(c: &mut Criterion) {
    c.bench_function("fsck/4096", |b| {
        let tmp = benchmark_tempdir();
        Queue::init(tmp.path(), &CreateOptions::default()).unwrap();
        let mut queue = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                deferred_dir_sync: true,
                ..Default::default()
            },
        )
        .unwrap();
        for _ in 0..4096 {
            assert!(matches!(
                queue.enqueue(EnqueueInput {
                    maximum_attempts: 3,
                    content_type: "x".into(),
                    payload: vec![0; 64],
                    ..Default::default()
                }),
                EnqueueOutcome::Deferred(_)
            ));
        }
        queue.sync().unwrap();
        b.iter(|| {
            let report = queue.fsck(&steadq_core::FsckOptions::default());
            assert_eq!(report.total_objects, 4096);
            assert!(report.findings.is_empty());
            black_box(report);
        });
    });
}

fn bench_lease_empty(c: &mut Criterion) {
    let mut group = c.benchmark_group("lease_empty");
    for shard_count in [16u32, 64, 256].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(shard_count),
            shard_count,
            |b, &sc| {
                b.iter_batched(
                    || {
                        let tmp = benchmark_tempdir();
                        Queue::init(
                            tmp.path(),
                            &CreateOptions {
                                shard_count: sc,
                                ..Default::default()
                            },
                        )
                        .unwrap();
                        let q = Queue::open(
                            tmp.path(),
                            &OpenOptions {
                                allow_unsupported_fs: true,
                                ..Default::default()
                            },
                        )
                        .unwrap();
                        (tmp, q)
                    },
                    |(_tmp, mut q)| {
                        let outcome = q.lease(0, 30_000_000_000);
                        assert!(matches!(outcome, LeaseOutcome::Empty));
                        black_box(outcome);
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

// An idle poll on one open handle, so queue setup and teardown stay out of
// the measured time.
fn bench_lease_empty_steady(c: &mut Criterion) {
    let mut group = c.benchmark_group("lease_empty_steady");
    for shard_count in [64u32, 256].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(shard_count),
            shard_count,
            |b, &sc| {
                let tmp = benchmark_tempdir();
                Queue::init(
                    tmp.path(),
                    &CreateOptions {
                        shard_count: sc,
                        ..Default::default()
                    },
                )
                .unwrap();
                let mut q = Queue::open(
                    tmp.path(),
                    &OpenOptions {
                        allow_unsupported_fs: true,
                        ..Default::default()
                    },
                )
                .unwrap();
                b.iter(|| {
                    let outcome = q.lease(0, 30_000_000_000);
                    assert!(matches!(outcome, LeaseOutcome::Empty));
                    black_box(outcome);
                });
            },
        );
    }
    group.finish();
}

fn bench_lease_hit(c: &mut Criterion) {
    let mut group = c.benchmark_group("lease_hit");
    for n_jobs in [1u32, 10, 100].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(n_jobs), n_jobs, |b, &n| {
            b.iter_batched(
                || {
                    let tmp = benchmark_tempdir();
                    Queue::init(tmp.path(), &CreateOptions::default()).unwrap();
                    let mut q = Queue::open(
                        tmp.path(),
                        &OpenOptions {
                            allow_unsupported_fs: true,
                            ..Default::default()
                        },
                    )
                    .unwrap();
                    for _ in 0..n {
                        q.enqueue(EnqueueInput {
                            maximum_attempts: 3,
                            content_type: "x".to_string(),
                            payload: b"data".to_vec(),
                            ..Default::default()
                        });
                    }
                    (tmp, q)
                },
                |(_tmp, mut q)| {
                    let outcome = q.lease(0, 30_000_000_000);
                    assert!(matches!(outcome, LeaseOutcome::Leased(_)));
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_ack(c: &mut Criterion) {
    c.bench_function("ack", |b| {
        b.iter_batched(
            || {
                let tmp = benchmark_tempdir();
                Queue::init(tmp.path(), &CreateOptions::default()).unwrap();
                let mut q = Queue::open(
                    tmp.path(),
                    &OpenOptions {
                        allow_unsupported_fs: true,
                        ..Default::default()
                    },
                )
                .unwrap();
                q.enqueue(EnqueueInput {
                    maximum_attempts: 3,
                    content_type: "x".to_string(),
                    payload: b"data".to_vec(),
                    ..Default::default()
                });
                let lease = match q.lease(0, 30_000_000_000) {
                    LeaseOutcome::Leased(l) => l,
                    _ => panic!("lease failed"),
                };
                (tmp, q, lease)
            },
            |(_tmp, mut q, lease)| {
                q.verify_lease_payload(&lease).unwrap();
                let outcome = q.ack(&lease);
                assert!(matches!(outcome, steadq_core::AckOutcome::Acked));
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_sustained_enqueue(c: &mut Criterion) {
    let mut group = c.benchmark_group("sustained_enqueue");
    for payload_size in [64usize, 1024, 16384].iter() {
        group.throughput(criterion::Throughput::Bytes(*payload_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(payload_size),
            payload_size,
            |b, &size| {
                let tmp = benchmark_tempdir();
                Queue::init(tmp.path(), &CreateOptions::default()).unwrap();
                let mut q = Queue::open(
                    tmp.path(),
                    &OpenOptions {
                        allow_unsupported_fs: true,
                        ..Default::default()
                    },
                )
                .unwrap();
                let payload = vec![0xABu8; size];
                b.iter(|| {
                    let outcome = q.enqueue(EnqueueInput {
                        maximum_attempts: 3,
                        content_type: "x".to_string(),
                        payload: payload.clone(),
                        ..Default::default()
                    });
                    assert!(matches!(outcome, EnqueueOutcome::Committed(_)));
                    black_box(outcome);
                });
            },
        );
    }
    group.finish();
}

fn bench_sustained_ack(c: &mut Criterion) {
    c.bench_function("sustained_ack", |b| {
        let tmp = benchmark_tempdir();
        Queue::init(tmp.path(), &CreateOptions::default()).unwrap();
        let mut q = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        b.iter(|| {
            q.enqueue(EnqueueInput {
                maximum_attempts: 3,
                content_type: "x".to_string(),
                payload: b"data".to_vec(),
                ..Default::default()
            });
            let lease = match q.lease(0, 30_000_000_000) {
                LeaseOutcome::Leased(l) => l,
                _ => panic!("lease failed"),
            };
            q.verify_lease_payload(&lease).unwrap();
            q.ack(&lease);
        });
    });
}

fn bench_sustained_completed(c: &mut Criterion) {
    let mut group = c.benchmark_group("sustained_completed");
    group.warm_up_time(std::time::Duration::from_secs(2));
    group.measurement_time(std::time::Duration::from_secs(10));
    group.sample_size(30);
    for payload_size in [64usize, 1024, 16384].iter() {
        group.throughput(criterion::Throughput::Bytes(*payload_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(payload_size),
            payload_size,
            |b, &size| {
                let tmp = benchmark_tempdir();
                Queue::init(tmp.path(), &CreateOptions::default()).unwrap();
                let mut q = Queue::open(
                    tmp.path(),
                    &OpenOptions {
                        allow_unsupported_fs: true,
                        ..Default::default()
                    },
                )
                .unwrap();
                let payload = vec![0xABu8; size];
                b.iter(|| {
                    enqueue_one(&mut q, &payload);
                    let lease = lease_one(&mut q);
                    q.verify_lease_payload(&lease).unwrap();
                    ack_one(&mut q, &lease);
                });
            },
        );
    }
    group.finish();
}

fn bench_concurrent_completed(c: &mut Criterion) {
    use std::sync::{Arc, Barrier};
    use std::thread;

    let mut group = c.benchmark_group("concurrent_completed");
    for &payload_size in &[64usize, 1024, 16384] {
        for &n_threads in &[1u32, 4, 8] {
            group.throughput(criterion::Throughput::Elements(u64::from(n_threads)));
            let label = format!("{payload_size}B_{n_threads}t");
            group.bench_with_input(
                BenchmarkId::from_parameter(label),
                &(payload_size, n_threads),
                |b, &(size, n)| {
                    let tmp = benchmark_tempdir();
                    Queue::init(tmp.path(), &CreateOptions::default()).unwrap();
                    let path = tmp.path().to_path_buf();
                    b.iter_custom(|iters| {
                        let publish_barrier = Arc::new(Barrier::new(n as usize));
                        let start = std::time::Instant::now();

                        let handles: Vec<_> = (0..n)
                            .map(|_| {
                                let p = path.clone();
                                let publish_barrier = Arc::clone(&publish_barrier);
                                thread::spawn(move || {
                                    let mut queue = Queue::open(
                                        &p,
                                        &OpenOptions {
                                            allow_unsupported_fs: true,
                                            ..Default::default()
                                        },
                                    )
                                    .unwrap();
                                    let payload = vec![0xABu8; size];
                                    for _ in 0..iters {
                                        enqueue_one(&mut queue, &payload);
                                    }
                                    publish_barrier.wait();
                                    for _ in 0..iters {
                                        let lease = lease_one(&mut queue);
                                        queue.verify_lease_payload(&lease).unwrap();
                                        ack_one(&mut queue, &lease);
                                    }
                                    iters
                                })
                            })
                            .collect();
                        let completed: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();
                        assert_eq!(completed, u64::from(n) * iters);
                        start.elapsed()
                    });
                },
            );
        }
    }
    group.finish();
}

fn bench_deferred_completed(c: &mut Criterion) {
    let mut group = c.benchmark_group("deferred_completed");
    for &payload_size in &[64usize, 16384] {
        group.throughput(criterion::Throughput::Bytes(payload_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(payload_size),
            &payload_size,
            |b, &size| {
                let tmp = benchmark_tempdir();
                Queue::init(tmp.path(), &CreateOptions::default()).unwrap();
                let mut q = Queue::open(
                    tmp.path(),
                    &OpenOptions {
                        allow_unsupported_fs: true,
                        deferred_dir_sync: true,
                        ..Default::default()
                    },
                )
                .unwrap();
                let payload = vec![0xABu8; size];
                b.iter(|| {
                    q.enqueue(EnqueueInput {
                        maximum_attempts: 3,
                        content_type: "x".to_string(),
                        payload: payload.clone(),
                        ..Default::default()
                    });
                    let lease = match q.lease(0, 30_000_000_000) {
                        LeaseOutcome::Leased(l) => l,
                        _ => panic!("lease failed"),
                    };
                    q.verify_lease_payload(&lease).unwrap();
                    q.ack(&lease);
                    q.sync().unwrap();
                });
            },
        );
    }
    group.finish();
}

fn completed_deferred(queue: &mut Queue, payload: &[u8]) {
    match queue.enqueue(EnqueueInput {
        maximum_attempts: 3,
        content_type: "x".to_string(),
        payload: payload.to_vec(),
        ..Default::default()
    }) {
        EnqueueOutcome::Committed(_) | EnqueueOutcome::Deferred(_) => {}
        outcome => panic!("enqueue failed: {outcome:?}"),
    }
    let lease = match queue.lease(0, 30_000_000_000) {
        LeaseOutcome::Leased(lease) => lease,
        outcome => panic!("lease failed: {outcome:?}"),
    };
    queue.verify_lease_payload(&lease).unwrap();
    match queue.ack(&lease) {
        AckOutcome::Acked => {}
        outcome => panic!("ack failed: {outcome:?}"),
    }
}

fn bench_batch_deferred_completed(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_deferred_completed");
    group.warm_up_time(std::time::Duration::from_secs(2));
    group.measurement_time(std::time::Duration::from_secs(10));
    group.sample_size(30);
    for &batch_size in &[1u32, 10, 50] {
        group.throughput(criterion::Throughput::Elements(u64::from(batch_size)));
        group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            &batch_size,
            |b, &n| {
                let tmp = benchmark_tempdir();
                Queue::init(tmp.path(), &CreateOptions::default()).unwrap();
                let mut q = Queue::open(
                    tmp.path(),
                    &OpenOptions {
                        allow_unsupported_fs: true,
                        deferred_dir_sync: true,
                        ..Default::default()
                    },
                )
                .unwrap();
                let payload = vec![0xABu8; 64];
                b.iter(|| {
                    for _ in 0..n {
                        completed_deferred(&mut q, &payload);
                    }
                    q.sync().unwrap();
                });
            },
        );
    }
    group.finish();
}

fn bench_batch_deferred(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_deferred");
    for &batch_size in &[1u32, 10, 50] {
        group.throughput(criterion::Throughput::Elements(batch_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            &batch_size,
            |b, &n| {
                let tmp = benchmark_tempdir();
                Queue::init(tmp.path(), &CreateOptions::default()).unwrap();
                let mut q = Queue::open(
                    tmp.path(),
                    &OpenOptions {
                        allow_unsupported_fs: true,
                        deferred_dir_sync: true,
                        ..Default::default()
                    },
                )
                .unwrap();
                b.iter(|| {
                    for _ in 0..n {
                        q.enqueue(EnqueueInput {
                            maximum_attempts: 3,
                            content_type: "x".to_string(),
                            payload: b"data".to_vec(),
                            ..Default::default()
                        });
                    }
                    q.sync().unwrap();
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_fsck,
    bench_enqueue,
    bench_lease_empty,
    bench_lease_empty_steady,
    bench_lease_hit,
    bench_ack,
    bench_sustained_enqueue,
    bench_sustained_ack,
    bench_concurrent_throughput,
    bench_sustained_completed,
    bench_concurrent_completed,
    bench_deferred_completed,
    bench_batch_deferred,
    bench_batch_deferred_completed,
);
criterion_main!(benches);

fn bench_concurrent_throughput(c: &mut Criterion) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

    let mut group = c.benchmark_group("concurrent");
    for n_threads in [1u32, 2, 4, 8].iter() {
        group.throughput(criterion::Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(n_threads),
            n_threads,
            |b, &n| {
                b.iter_custom(|iters| {
                    let tmp = benchmark_tempdir();
                    Queue::init(tmp.path(), &CreateOptions::default()).unwrap();
                    let path = tmp.path().to_path_buf();
                    let total = Arc::new(AtomicUsize::new(0));
                    let start = std::time::Instant::now();

                    let handles: Vec<_> = (0..n)
                        .map(|_| {
                            let p = path.clone();
                            let t = total.clone();
                            thread::spawn(move || {
                                let queue = Queue::open(
                                    &p,
                                    &OpenOptions {
                                        allow_unsupported_fs: true,
                                        ..Default::default()
                                    },
                                )
                                .unwrap();
                                let mut queue = queue;
                                let mut local = 0usize;
                                for _ in 0..iters {
                                    if matches!(
                                        queue.enqueue(EnqueueInput {
                                            maximum_attempts: 3,
                                            content_type: "x".to_string(),
                                            payload: b"data".to_vec(),
                                            ..Default::default()
                                        }),
                                        EnqueueOutcome::Committed(_)
                                    ) {
                                        local += 1;
                                    }
                                }
                                t.fetch_add(local, Ordering::Relaxed);
                            })
                        })
                        .collect();
                    for h in handles {
                        h.join().unwrap();
                    }
                    let elapsed = start.elapsed();
                    // Keep temp dir alive for the measurement
                    drop(tmp);
                    elapsed
                });
            },
        );
    }
    group.finish();
}
