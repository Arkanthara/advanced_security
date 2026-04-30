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
#  Single timed measurement
# ══════════════════════════════════════════════════════════════════

def _measure_once(y: int, x: int, n: int) -> float:
    """
    One timed call to square_and_multiply with GC disabled.

    Parameters
    ----------
    y, x, n : int   See square_and_multiply.

    Returns
    -------
    float
        Elapsed time in nanoseconds.
    """
    gc.disable()
    try:
        t0 = time.perf_counter_ns()
        square_and_multiply(y, x, n)
        return float(time.perf_counter_ns() - t0)
    finally:
        gc.enable()


def timed_server_call(y: int, x: int, n: int, reps: int = 7) -> float:
    """
    Robust server timing: median of ``reps`` measurements after outlier removal.

    A short sleep between repetitions lets the system stabilise so transient
    OS load does not systematically bias a particular call.

    Parameters
    ----------
    y    : int   Base input.
    x    : int   Secret exponent (server side).
    n    : int   Modulus.
    reps : int   Number of raw measurements to take.

    Returns
    -------
    float
        Robust median elapsed time in nanoseconds.
    """
    raw = []
    for _ in range(reps):
        raw.append(_measure_once(y, x, n))
        time.sleep(1e-5)  # tiny stabilisation pause

    arr = np.array(raw)
    # Remove outliers via 1.5×IQR fence
    q1, q3 = np.percentile(arr, [25, 75])
    iqr = q3 - q1
    mask = (arr >= q1 - 1.5 * iqr) & (arr <= q3 + 1.5 * iqr)
    return float(np.median(arr[mask]) if mask.sum() > 0 else np.median(arr))


# ══════════════════════════════════════════════════════════════════
#  Timing data collection  (parallel)
# ══════════════════════════════════════════════════════════════════

def collect_timing_data(
    ys: list, x: int, n: int,
    reps: int = 7, n_jobs: int = -1
) -> np.ndarray:
    """
    Query the server for each y_i in parallel and record T_i.

    Parameters
    ----------
    ys     : list   Random query inputs y_0 … y_{m-1}.
    x      : int    Secret exponent (lives on the server).
    n      : int    Modulus.
    reps   : int    Repetitions per sample for robust timing.
    n_jobs : int    Parallel workers (-1 = all available CPUs).

    Returns
    -------
    np.ndarray
        Shape (m,) array of timing measurements T_i in nanoseconds.
    """
    print("\nCollecting server timing data…")
    results = Parallel(n_jobs=n_jobs)(
        delayed(timed_server_call)(y, x, n, reps)
        for y in tqdm(ys, desc="  Samples", unit="y")
    )
    return np.array(results)


# ══════════════════════════════════════════════════════════════════
#  Partial-time simulation
# ══════════════════════════════════════════════════════════════════

def _partial_time_once(y: int, bits: list, n: int) -> float:
    """
    Time exactly len(bits) iterations of square_and_multiply for input y.

    This reproduces steps 0..b of the server loop with the hypothesised
    prefix, giving t(y_i, x_b).

    Parameters
    ----------
    y    : int    Base input.
    bits : list   Hypothesised bits [x_0, x_1, …, x_b] (LSB first).
    n    : int    Modulus.

    Returns
    -------
    float
        Elapsed time in nanoseconds.
    """
    gc.disable()
    try:
        s = 1
        yy = y % n
        t0 = time.perf_counter_ns()
        for bit in bits:
            if bit:
                s = (s * yy) % n
            yy = (yy * yy) % n
        return float(time.perf_counter_ns() - t0)
    finally:
        gc.enable()


def simulate_partial_time(y: int, bits: list, n: int, reps: int = 7) -> float:
    """
    Robust partial-time estimate for one sample (median of reps runs).

    Parameters
    ----------
    y    : int    Base input.
    bits : list   Hypothesised prefix bits (LSB first).
    n    : int    Modulus.
    reps : int    Repetitions for the median.

    Returns
    -------
    float
        Median partial time in nanoseconds.
    """
    return float(np.median([_partial_time_once(y, bits, n) for _ in range(reps)]))


def compute_partial_times(
    ys: list, bits: list, n: int,
    reps: int = 7, n_jobs: int = -1
) -> np.ndarray:
    """
    Compute the partial-time vector t(y_i, hyp) for all m inputs in parallel.

    Parameters
    ----------
    ys     : list   Query inputs.
    bits   : list   Hypothesised prefix bits including current candidate bit.
    n      : int    Modulus.
    reps   : int    Repetitions per sample.
    n_jobs : int    Parallel workers.

    Returns
    -------
    np.ndarray
        Shape (m,) partial times in nanoseconds.
    """
    results = Parallel(n_jobs=n_jobs)(
        delayed(simulate_partial_time)(y, bits, n, reps) for y in ys
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
    reps: int = 7, n_jobs: int = -1
) -> list:
    """
    Recover exponent bits one at a time via minimum-variance selection.

    For bit b with prefix already recovered = [x_0, …, x_{b-1}]:
      1. Form candidate prefix [x_0, …, x_{b-1}, h] for h ∈ {0, 1}.
      2. Compute partial times for both hypotheses.
      3. Choose h with lower Var(T − t).

    Parameters
    ----------
    ys         : list         Query inputs.
    full_times : np.ndarray   Measured T_i.
    n          : int          Modulus.
    num_bits   : int          Exponent bit-length to recover.
    reps       : int          Partial-timing repetitions.
    n_jobs     : int          Parallel workers.

    Returns
    -------
    list
        Recovered bits [x_0, x_1, …, x_{w-1}] in LSB-first order.
    """
    recovered = []
    pbar = tqdm(range(num_bits), desc="V1 bit recovery")

    for _ in pbar:
        vars_ = {}
        for hyp in (0, 1):
            candidate = recovered + [hyp]
            partial = compute_partial_times(ys, candidate, n, reps, n_jobs)
            vars_[hyp] = residual_variance(full_times, partial)

        chosen = min(vars_, key=vars_.get)
        recovered.append(chosen)
        pbar.set_postfix(
            bit=chosen,
            var0=f"{vars_[0]:.2e}",
            var1=f"{vars_[1]:.2e}",
            diff=f"{abs(vars_[0]-vars_[1]):.2e}",
        )

    return recovered


# ══════════════════════════════════════════════════════════════════
#  Attack V2 – beam search with error correction
# ══════════════════════════════════════════════════════════════════

def attack_v2(
    ys: list, full_times: np.ndarray,
    n: int, num_bits: int,
    beam_width: int = 10, reps: int = 7, n_jobs: int = -1
) -> list:
    """
    Recover exponent bits with beam search to allow error correction.

    At each step every live candidate is extended by both 0 and 1.
    Only the ``beam_width`` candidates with the lowest residual variance
    survive to the next step.

    Theory: if the first c bits of a wrong hypothesis accidentally match,
    its residual variance is Var(noise) + (w−b+2c)·Var(t_j), which is
    strictly larger than a fully correct hypothesis.  Keeping multiple
    candidates allows the search to recover from early mistakes.

    Parameters
    ----------
    ys         : list         Query inputs.
    full_times : np.ndarray   Measured T_i.
    n          : int          Modulus.
    num_bits   : int          Exponent bit-length to recover.
    beam_width : int          Number of candidate prefixes to keep per step.
    reps       : int          Partial-timing repetitions.
    n_jobs     : int          Parallel workers.

    Returns
    -------
    list
        Best recovered bits [x_0, …, x_{w-1}] in LSB-first order.
    """
    # Beam entries: (variance, bit_prefix_list)
    beam = [(0.0, [])]

    pbar = tqdm(range(num_bits), desc="V2 beam recovery")
    for _ in pbar:
        next_candidates = []

        for _, prefix in beam:
            for hyp in (0, 1):
                candidate = prefix + [hyp]
                partial = compute_partial_times(ys, candidate, n, reps, n_jobs)
                var = residual_variance(full_times, partial)
                next_candidates.append((var, candidate))

        # Keep best beam_width by lowest variance
        next_candidates.sort(key=lambda t: t[0])
        beam = next_candidates[:beam_width]

        best_var, best_bits = beam[0]
        pbar.set_postfix(
            best_var=f"{best_var:.2e}",
            beam_spread=f"{beam[-1][0] - beam[0][0]:.2e}",
            current_int=bits_to_int(best_bits),
        )

    return beam[0][1]  # best candidate


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
    rsa_instance.createKeyPair(size=64)         # 32-bit key → fast demo
    [e, n], [d, _] = rsa_instance.getKeys()
    print(f"Generated RSA key pair: n={n}, e={e}, d={d}")

    NUM_BITS    = d.bit_length()  # exponent size to recover
    NUM_SAMPLES = 150             # number of distinct query inputs
    REPS        = 5               # repetitions per timing measurement
    BEAM_WIDTH  = 8               # V2 beam width
    N_JOBS      = -1              # use all CPUs

    print("=" * 60)
    print("  RSA Timing Attack Demo")
    print("=" * 60)
    print(f"  n          = {n}")
    print(f"  Secret d   = {d}  ({NUM_BITS} bits)")
    print(f"  Samples    = {NUM_SAMPLES}")
    print(f"  Reps/sample= {REPS}")
    print("=" * 60)

    # ── 1. Random query inputs ────────────────────────────────────────────────
    ys = [random.randint(2, n - 1) for _ in range(NUM_SAMPLES)]

    # ── 2. Collect full server timings T_i ───────────────────────────────────
    full_times = collect_timing_data(ys, d, n, reps=REPS, n_jobs=N_JOBS)
    print(f"\n  Timing stats: mean={full_times.mean():.0f} ns, "
          f"std={full_times.std():.0f} ns")

    # ── 3. Version 1 – greedy recovery ───────────────────────────────────────
    print("\n" + "─" * 60)
    print("  Attack V1 – Greedy (minimum variance)")
    print("─" * 60)
    recovered_v1 = attack_v1(ys, full_times, n, NUM_BITS, reps=REPS, n_jobs=N_JOBS)
    evaluate_recovery(recovered_v1, d, "V1")

    # ── 4. Version 2 – beam search recovery ──────────────────────────────────
    print("\n" + "─" * 60)
    print(f"  Attack V2 – Beam search (width={BEAM_WIDTH})")
    print("─" * 60)
    recovered_v2 = attack_v2(
        ys, full_times, n, NUM_BITS,
        beam_width=BEAM_WIDTH, reps=REPS, n_jobs=N_JOBS
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
