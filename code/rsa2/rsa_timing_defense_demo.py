"""RSA timing-defense demo: vulnerable vs constant-time exponentiation.

This script compares a secret-dependent square-and-multiply routine with a
branch-free Montgomery-ladder-style routine. It measures timing over many
random bases, reduces noise with repeated measurements, removes outliers,
and reports basic summary statistics.

Dependencies
------------
- numpy
- joblib
- tqdm

Notes
-----
- Python big integers are not truly constant-time, so this is a *defense
  demo*, not a formal side-channel proof.
- The goal is to show that removing secret-dependent branches reduces
  timing variability.
"""

from __future__ import annotations

import gc
import random
import time
from dataclasses import dataclass
from statistics import median

import numpy as np
from joblib import Parallel, delayed
from tqdm import tqdm


def fast_exp_vulnerable(y: int, x: int, n: int) -> int:
    """Square-and-multiply with secret-dependent branching."""
    s = 1
    y %= n
    while x > 0:
        if x & 1:
            s = (s * y) % n
        y = (y * y) % n
        x >>= 1
    return s


def fast_exp_ct(y: int, x: int, n: int) -> int:
    """Branch-free Montgomery-ladder-style modular exponentiation."""
    r0, r1 = 1, y % n
    for i in range(x.bit_length() - 1, -1, -1):
        bit = (x >> i) & 1
        a = (r0 * r1) % n
        b = (r0 * r0) % n
        c = (r1 * r1) % n
        # Branch-free selection in Python syntax.
        r0 = bit * a + (1 - bit) * b
        r1 = bit * c + (1 - bit) * a
    return r0


@dataclass
class Sample:
    """A single timing sample."""

    y: int
    ns: float


def _single_measurement(y: int, x: int, n: int, repeat: int, sleep_s: float, fn) -> Sample:
    """Measure one input several times and return the median duration."""
    times = []
    for _ in range(repeat):
        t0 = time.perf_counter_ns()
        fn(y, x, n)
        t1 = time.perf_counter_ns()
        times.append(t1 - t0)
        if sleep_s:
            time.sleep(sleep_s)

    # IQR-based outlier removal.
    arr = np.asarray(times, dtype=np.float64)
    q1, q3 = np.percentile(arr, [25, 75])
    iqr = q3 - q1
    if iqr > 0:
        lo, hi = q1 - 1.5 * iqr, q3 + 1.5 * iqr
        arr = arr[(arr >= lo) & (arr <= hi)]
    return Sample(y=y, ns=float(median(arr.tolist())))


def collect_samples(fn, x: int, n: int, m: int = 200, repeat: int = 7, sleep_s: float = 1e-4,
                    n_jobs: int = -1, seed: int = 0) -> list[Sample]:
    """Collect timing samples for random bases."""
    rng = random.Random(seed)
    ys = [rng.randrange(2, n - 1) for _ in range(m)]

    gc_was_enabled = gc.isenabled()
    gc.disable()
    try:
        samples = Parallel(n_jobs=n_jobs, prefer="threads")(
            delayed(_single_measurement)(y, x, n, repeat, sleep_s, fn)
            for y in tqdm(ys, desc=fn.__name__, leave=True)
        )
    finally:
        if gc_was_enabled:
            gc.enable()

    return samples


def summarize(samples: list[Sample]) -> dict[str, float]:
    """Return simple summary statistics in nanoseconds."""
    values = np.array([s.ns for s in samples], dtype=np.float64)
    return {
        "mean_ns": float(values.mean()),
        "median_ns": float(np.median(values)),
        "std_ns": float(values.std(ddof=1)),
        "min_ns": float(values.min()),
        "max_ns": float(values.max()),
    }


def print_report(name: str, stats: dict[str, float]) -> None:
    """Pretty-print a timing summary."""
    print(f"\n{name}")
    print("-" * len(name))
    for k, v in stats.items():
        print(f"{k:>10}: {v:,.2f}")


def main() -> None:
    """Run the timing comparison."""
    # Small RSA-sized toy modulus for a quick demo.
    # Replace with a real RSA modulus if you want a heavier benchmark.
    p = 18446744073709551557  # prime near 2^64
    q = 18446744073709551533  # prime near 2^64
    n = p * q

    # Secret exponent for the benchmark.
    x = random.getrandbits(1024)

    print("Collecting timings. This may take a moment...\n")

    vuln = collect_samples(fast_exp_vulnerable, x, n, m=120, repeat=5, sleep_s=1e-4)
    const = collect_samples(fast_exp_ct, x, n, m=120, repeat=5, sleep_s=1e-4)

    vuln_stats = summarize(vuln)
    const_stats = summarize(const)

    print_report("Vulnerable square-and-multiply", vuln_stats)
    print_report("Constant-time style ladder", const_stats)

    ratio = vuln_stats["std_ns"] / const_stats["std_ns"] if const_stats["std_ns"] else float("inf")
    print(f"\nStd-dev ratio (vulnerable / constant-time): {ratio:.2f}x")


if __name__ == "__main__":
    main()
