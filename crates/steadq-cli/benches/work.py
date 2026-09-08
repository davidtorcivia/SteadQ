"""Time 50 one-byte jobs: python3 crates/steadq-cli/benches/work.py target/debug/steadq."""

import statistics
import subprocess
import sys
import tempfile
import time

binary = sys.argv[1]
times = []
for _ in range(3):
    with tempfile.TemporaryDirectory() as queue:
        subprocess.run([binary, "init", queue], check=True, capture_output=True, timeout=10)
        for _ in range(50):
            subprocess.run(
                [binary, "put", queue, "-"],
                input=b"x", check=True, capture_output=True, timeout=10,
            )
        start = time.monotonic()
        for _ in range(50):
            subprocess.run(
                [binary, "work", queue, "--once", "--concurrency", "1", "--", "true"],
                check=True, capture_output=True, timeout=10,
            )
        times.append(time.monotonic() - start)
print(f"Seconds: {times}; median: {statistics.median(times):.6f}")
