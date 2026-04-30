"""
RSA Timing Attack – Square-and-Multiply Exponent Recovery
==========================================================

Demonstrates Kocher's timing attack on RSA square-and-multiply exponentiation.

Theory
------
For y_i^x mod n the server time is:
    T_i = noise + sum_{j=0}^{w-1} t_j(y_i)

where t_j(y_i) is the cost of iteration j (slightly larger when bit x_j = 1
because an extra modular multiplication is performed).

The attacker knows bits 0..b-1 and wants to determine bit b.
He computes the expected partial contribution:
    t(y_i, hyp) = sum_{j=0}^{b} t_j(y_i) under hypothesis hyp ∈ {0,1}

Then forms the residual:
    T'_i = T_i − t(y_i, hyp)

  • If hyp is correct → T'_i = noise + remaining bits  → lower variance
  • If hyp is wrong   → the subtracted term is misaligned → higher variance

Two recovery strategies
-----------------------
  V1 – Greedy:      Pick the hypothesis with lower Var(T') at each bit.
  V2 – Beam search: Keep the top-k lowest-variance prefixes for error correction.
"""

import gc
import time
import random
import numpy as np
from tqdm import tqdm
from joblib import Parallel, delayed

from rsa import RSA  # provided RSA class


# ══════════════════════════════════════════════════════════════════
#  Vulnerable server
# ══════════════════════════════════════════════════════════════════

def square_and_multiply(y: int, x: int, n: int) -> int:
    """
    LSB-first square-and-multiply exponentiation – the 'server' function.

    The timing leak: the multiply ``s = (s * y) % n`` only executes when the
    current exponent bit is 1, creating a measurable per-bit time difference.

    Parameters
    ----------
    y : int   Base.
    x : int   Secret exponent.
    n : int   Modulus.

    Returns
    -------
    int
        y**x mod n
    """
    s = 1
    y %= n
    while x > 0:
        if x & 1:               # ← timing leak: extra multiply when bit = 1
            s = (s * y) % n
        y = (y * y) % n         # always square
        x >>= 1
    return s


# ══════════════════════════════════════════════════════════════════
#  Timing helpers
# ══════════════════════════════════════════════════════════════════

def iqr_filter(data: np.ndarray, factor: float = 1.0) -> np.ndarray:
    """
    Remove outliers outside ``factor`` × IQR from Q1/Q3.

    A tighter fence (factor=1.0 vs the common 1.5) is intentional:
    system-noise spikes are much larger than the crypto signal, so we
    want to be aggressive about discarding them.

    Parameters
    ----------
    data   : np.ndarray  1-D array of timing samples.
    factor : float       IQR multiplier for the fence.

    Returns
    -------
    np.ndarray
        Filtered array (falls back to full data if too many removed).
    """
    q1, q3 = np.percentile(data, [25, 75])
    iqr = q3 - q1
    if iqr == 0:
        return data
    lo, hi = q1 - factor * iqr, q3 + factor * iqr
    filtered = data[(data >= lo) & (data <= hi)]
    # Safety: never discard more than half the samples
    return filtered if len(filtered) >= len(data) * 0.5 else data


def timed_server_call(
    y: int, x: int, n: int,
    amplification: int = 1000, num_runs: int = 3
) -> float:
    """
    Robust server timing via **amplification loop**.

    Instead of timing one call (which drowns in ``perf_counter`` overhead),
    we time a tight loop of ``amplification`` calls and divide.  The per-call
    noise is reduced by ~√amplification.  We repeat ``num_runs`` times and
    take the IQR-filtered median.

    Parameters
    ----------
    y             : int   Base input.
    x             : int   Secret exponent (server side).
    n             : int   Modulus.
    amplification : int   Calls per timed block (1000 recommended).
    num_runs      : int   Independent timed blocks to median over.

    Returns
    -------
    float
        Robust per-call time in nanoseconds.
    """
    # Warm up caches and branch predictor before measuring
    for _ in range(10):
        square_and_multiply(y, x, n)

    gc.disable()
    try:
        raw = []
        for _ in range(num_runs):
            t0 = time.perf_counter_ns()
            for _ in range(amplification):
                square_and_multiply(y, x, n)
            raw.append((time.perf_counter_ns() - t0) / amplification)
            time.sleep(1e-3)   # let the CPU settle between blocks
        return float(np.median(iqr_filter(np.array(raw))))
    finally:
        gc.enable()


# ══════════════════════════════════════════════════════════════════
#  Timing data collection  (parallel)
# ══════════════════════════════════════════════════════════════════

def collect_timing_data(
    ys: list, x: int, n: int,
    amplification: int = 1000, num_runs: int = 3, n_jobs: int = -1
) -> np.ndarray:
    """
    Query the server for each y_i in parallel and record T_i.

    Parameters
    ----------
    ys            : list   Random query inputs y_0 … y_{m-1}.
    x             : int    Secret exponent (lives on the server).
    n             : int    Modulus.
    amplification : int    Calls per timed block.
    num_runs      : int    Independent timed blocks per sample.
    n_jobs        : int    Parallel workers (-1 = all available CPUs).

    Returns
    -------
    np.ndarray
        Shape (m,) array of timing measurements T_i in nanoseconds.
    """
    print("\nCollecting server timing data…")
    results = Parallel(n_jobs=n_jobs)(
        delayed(timed_server_call)(y, x, n, amplification, num_runs)
        for y in tqdm(ys, desc="  Samples", unit="y")
    )
    return np.array(results)


# ══════════════════════════════════════════════════════════════════
#  Partial-time simulation
# ══════════════════════════════════════════════════════════════════

def simulate_partial_time(
    y: int, bits: list, n: int,
    amplification: int = 1000, num_runs: int = 3
) -> float:
    """
    Estimate t(y_i, hyp) = time for the first len(bits) loop iterations.

    Same amplification strategy as ``timed_server_call``: tight inner loop
    of ``amplification`` replays, repeated ``num_runs`` times, IQR-filtered
    median.  This ensures the partial-time scale matches the full-time scale
    so that the subtraction T_i − t(y_i, hyp) is meaningful.

    Parameters
    ----------
    y             : int    Base input.
    bits          : list   Hypothesised prefix bits [x_0, …, x_b] (LSB first).
    n             : int    Modulus.
    amplification : int    Replays per timed block.
    num_runs      : int    Independent timed blocks.

    Returns
    -------
    float
        Robust per-call partial time in nanoseconds.
    """
    # Warm up
    s, yy = 1, y % n
    for bit in bits:
        if bit:
            s = (s * yy) % n
        yy = (yy * yy) % n

    gc.disable()
    try:
        raw = []
        for _ in range(num_runs):
            t0 = time.perf_counter_ns()
            for _ in range(amplification):
                s, yy = 1, y % n
                for bit in bits:
                    if bit:
                        s = (s * yy) % n
                    yy = (yy * yy) % n
            raw.append((time.perf_counter_ns() - t0) / amplification)
            time.sleep(1e-3)
        return float(np.median(iqr_filter(np.array(raw))))
    finally:
        gc.enable()


def compute_partial_times(
    ys: list, bits: list, n: int,
    amplification: int = 1000, num_runs: int = 3, n_jobs: int = -1
) -> np.ndarray:
    """
    Compute the partial-time vector t(y_i, hyp) for all m inputs in parallel.

    Parameters
    ----------
    ys            : list   Query inputs.
    bits          : list   Hypothesised prefix bits including current candidate.
    n             : int    Modulus.
    amplification : int    Replays per timed block.
    num_runs      : int    Independent timed blocks per sample.
    n_jobs        : int    Parallel workers.

    Returns
    -------
    np.ndarray
        Shape (m,) partial times in nanoseconds.
    """
    results = Parallel(n_jobs=n_jobs)(
        delayed(simulate_partial_time)(y, bits, n, amplification, num_runs)
        for y in ys
    )
    return np.array(results)


# ══════════════════════════════════════════════════════════════════
#  Variance helper
# ══════════════════════════════════════════════════════════════════

def residual_variance(full_times: np.ndarray, partial_times: np.ndarray) -> float:
    """
    Compute Var(T_i − t(y_i, hyp)).

    Lower variance ↔ hypothesis is consistent with the true exponent prefix.

    Parameters
    ----------
    full_times    : np.ndarray  T_i measurements.
    partial_times : np.ndarray  t(y_i, hyp) estimates.

    Returns
    -------
    float
        Variance of the residual T' = T − t.
    """
    return float(np.var(full_times - partial_times))


# ══════════════════════════════════════════════════════════════════
#  Attack V1 – greedy bit-by-bit recovery
# ══════════════════════════════════════════════════════════════════

def attack_v1(
    ys: list, full_times: np.ndarray,
    n: int, num_bits: int,
    amplification: int = 1000, num_runs: int = 3,
    filter_percentile: int = 20, n_jobs: int = -1
) -> list:
    """
    Recover exponent bits one at a time via minimum-variance selection.

    Key improvement over the naive version: **delta-based message filtering**.
    For each bit hypothesis we compute the *predicted* timing difference
    δ_i = |t(y_i, H1) − t(y_i, H0)|.  Only the top ``(100 − filter_percentile)``%
    of messages — those with the largest δ_i — are used for the variance test.
    Messages with a tiny predicted delta contribute only noise to the
    distinguisher and are discarded.

    Parameters
    ----------
    ys               : list         Query inputs.
    full_times       : np.ndarray   Measured T_i.
    n                : int          Modulus.
    num_bits         : int          Exponent bit-length to recover.
    amplification    : int          Replays per timed block.
    num_runs         : int          Independent timed blocks per sample.
    filter_percentile: int          Bottom X% by |δ| to discard (default 20).
    n_jobs           : int          Parallel workers.

    Returns
    -------
    list
        Recovered bits [x_0, x_1, …, x_{w-1}] in LSB-first order.
    """
    recovered = []
    pbar = tqdm(range(num_bits), desc="V1 bit recovery")

    for _ in pbar:
        # Compute partial times for BOTH hypotheses up front
        partial = {
            hyp: compute_partial_times(ys, recovered + [hyp], n,
                                       amplification, num_runs, n_jobs)
            for hyp in (0, 1)
        }

        # Delta filtering: keep only messages where the two hypotheses
        # produce a meaningfully different predicted time.
        # These are the messages most likely to expose the real bit value.
        deltas = np.abs(partial[1] - partial[0])
        threshold = np.percentile(deltas, filter_percentile)
        mask = deltas >= threshold                           # top 80% by default

        T_filtered = full_times[mask]
        vars_ = {hyp: residual_variance(T_filtered, partial[hyp][mask])
                 for hyp in (0, 1)}

        chosen = min(vars_, key=vars_.get)
        recovered.append(chosen)
        pbar.set_postfix(
            bit=chosen,
            var0=f"{vars_[0]:.2e}",
            var1=f"{vars_[1]:.2e}",
            diff=f"{abs(vars_[0]-vars_[1]):.2e}",
            kept=f"{mask.sum()}/{len(ys)}",
        )

    return recovered


# ══════════════════════════════════════════════════════════════════
#  Attack V2 – beam search with error correction
# ══════════════════════════════════════════════════════════════════

def attack_v2(
    ys: list, full_times: np.ndarray,
    n: int, num_bits: int,
    beam_width: int = 10,
    amplification: int = 1000, num_runs: int = 3,
    filter_percentile: int = 20, n_jobs: int = -1
) -> list:
    """
    Recover exponent bits with beam search and delta-based filtering.

    Combines the beam-search error correction with the same delta filtering
    used in V1: for each candidate prefix the mask of informative messages
    is computed per-step, so the variance signal used to rank candidates is
    as clean as possible.

    Parameters
    ----------
    ys               : list         Query inputs.
    full_times       : np.ndarray   Measured T_i.
    n                : int          Modulus.
    num_bits         : int          Exponent bit-length to recover.
    beam_width       : int          Candidate prefixes kept per step.
    amplification    : int          Replays per timed block.
    num_runs         : int          Independent timed blocks per sample.
    filter_percentile: int          Bottom X% by |δ| to discard.
    n_jobs           : int          Parallel workers.

    Returns
    -------
    list
        Best recovered bits [x_0, …, x_{w-1}] in LSB-first order.
    """
    beam = [(0.0, [])]  # (variance, bit_prefix)

    pbar = tqdm(range(num_bits), desc="V2 beam recovery")
    for _ in pbar:
        next_candidates = []

        for _, prefix in beam:
            # Compute partial times for both extensions in one pass
            partial = {
                hyp: compute_partial_times(ys, prefix + [hyp], n,
                                           amplification, num_runs, n_jobs)
                for hyp in (0, 1)
            }
            # Delta filtering per candidate
            deltas = np.abs(partial[1] - partial[0])
            threshold = np.percentile(deltas, filter_percentile)
            mask = deltas >= threshold

            T_filtered = full_times[mask]
            for hyp in (0, 1):
                var = residual_variance(T_filtered, partial[hyp][mask])
                next_candidates.append((var, prefix + [hyp]))

        next_candidates.sort(key=lambda t: t[0])
        beam = next_candidates[:beam_width]

        best_var, best_bits = beam[0]
        pbar.set_postfix(
            best_var=f"{best_var:.2e}",
            spread=f"{beam[-1][0] - beam[0][0]:.2e}",
            current_int=bits_to_int(best_bits),
        )

    return beam[0][1]


# ══════════════════════════════════════════════════════════════════
#  Utilities
# ══════════════════════════════════════════════════════════════════

def bits_to_int(bits: list) -> int:
    """
    Convert an LSB-first bit list to its integer value.

    Parameters
    ----------
    bits : list   Bit list where index 0 is the least significant bit.

    Returns
    -------
    int
    """
    return sum(b << i for i, b in enumerate(bits))


def evaluate_recovery(recovered: list, true_x: int, label: str) -> None:
    """
    Print bit-level accuracy and full-integer comparison.

    Parameters
    ----------
    recovered : list   Recovered bit list (LSB first).
    true_x    : int    True secret exponent.
    label     : str    Display label (e.g. "V1", "V2").
    """
    w = len(recovered)
    true_bits = [(true_x >> i) & 1 for i in range(w)]
    correct = sum(r == t for r, t in zip(recovered, true_bits))
    rec_int = bits_to_int(recovered)
    print(f"\n[{label}] True exponent  : {true_x}")
    print(f"[{label}] Recovered      : {rec_int}")
    print(f"[{label}] Bit accuracy   : {correct}/{w} ({100*correct/w:.1f}%)")
    print(f"[{label}] Exact match    : {rec_int == true_x}")


# ══════════════════════════════════════════════════════════════════
#  Main demo
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # ── Small RSA key for a feasible local demo ──────────────────────────────
    rsa_instance = RSA()
    rsa_instance.createKeyPair(size=32)         # 32-bit key → fast demo
    [e, n], [d, _] = rsa_instance.getKeys()

    NUM_BITS         = d.bit_length()  # exponent size to recover
    NUM_SAMPLES      = 200             # number of distinct query inputs
    AMPLIFICATION    = 1000            # calls per timed block  ← key fix
    NUM_RUNS         = 3               # timed blocks per sample
    FILTER_PERCENTILE= 20              # discard bottom 20% by |delta|  ← key fix
    BEAM_WIDTH       = 8               # V2 beam width
    N_JOBS           = -1              # use all CPUs

    print("=" * 60)
    print("  RSA Timing Attack Demo")
    print("=" * 60)
    print(f"  n              = {n}")
    print(f"  Secret d       = {d}  ({NUM_BITS} bits)")
    print(f"  Samples        = {NUM_SAMPLES}")
    print(f"  Amplification  = {AMPLIFICATION}×{NUM_RUNS} runs")
    print(f"  Delta filter   = keep top {100-FILTER_PERCENTILE}% messages")
    print("=" * 60)

    # ── 1. Random query inputs ────────────────────────────────────────────────
    ys = [random.randint(2, n - 1) for _ in range(NUM_SAMPLES)]

    # ── 2. Collect full server timings T_i ───────────────────────────────────
    full_times = collect_timing_data(
        ys, d, n, amplification=AMPLIFICATION, num_runs=NUM_RUNS, n_jobs=N_JOBS
    )
    print(f"\n  Timing stats: mean={full_times.mean():.0f} ns, "
          f"std={full_times.std():.0f} ns")

    # ── 3. Version 1 – greedy recovery ───────────────────────────────────────
    print("\n" + "─" * 60)
    print("  Attack V1 – Greedy (minimum variance + delta filter)")
    print("─" * 60)
    recovered_v1 = attack_v1(
        ys, full_times, n, NUM_BITS,
        amplification=AMPLIFICATION, num_runs=NUM_RUNS,
        filter_percentile=FILTER_PERCENTILE, n_jobs=N_JOBS
    )
    evaluate_recovery(recovered_v1, d, "V1")

    # ── 4. Version 2 – beam search recovery ──────────────────────────────────
    print("\n" + "─" * 60)
    print(f"  Attack V2 – Beam search (width={BEAM_WIDTH}) + delta filter")
    print("─" * 60)
    recovered_v2 = attack_v2(
        ys, full_times, n, NUM_BITS,
        beam_width=BEAM_WIDTH,
        amplification=AMPLIFICATION, num_runs=NUM_RUNS,
        filter_percentile=FILTER_PERCENTILE, n_jobs=N_JOBS
    )
    evaluate_recovery(recovered_v2, d, "V2")

    # ── 5. Challenge: use recovered key to decrypt ────────────────────────────
    print("\n" + "─" * 60)
    print("  Challenge decryption")
    print("─" * 60)
    challenge_cipher = rsa_instance.createChallenge()
    for label, bits in [("V1", recovered_v1), ("V2", recovered_v2)]:
        key_guess = bits_to_int(bits)
        try:
            plaintext = rsa_instance.decryptChallenge(key_guess)
            print(f"[{label}] ✓ Decrypted: {plaintext}")
        except Exception:
            print(f"[{label}] ✗ Decryption failed (key mismatch).")
