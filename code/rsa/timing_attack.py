"""
Kocher's Timing Attack on RSA (1996)
======================================

WHY DOES IT WORK?
-----------------
The fast_exp loop processes the secret exponent bit by bit (LSB first):

    while x > 0:
        if x & 1:                    ← bit = 1 → EXTRA multiplication (slower)
            s = (s * y) % n
        y = (y * y) % n              ← always done
        x >>= 1

When bit b = 1, the server does one extra modular multiplication.
That extra work leaks through timing.

STATISTICAL STRATEGY (per bit b, knowing bits 0..b-1)
------------------------------------------------------
Let T_i   = total server time for input y_i
    t_j   = time for iteration j (includes extra mult if bit j = 1)
    T_i   = noise + Σ_{j=0}^{w-1} t_j

We hypothesize bit b, simulate the first b+1 iterations locally,
and subtract that estimate from T_i:

    T'_i = T_i - t(y_i, hypothesis)

• Hypothesis CORRECT  → T'_i = noise + Σ_{j=b+1}^{w-1} t_j   → low variance
• Hypothesis WRONG    → residuals are corrupted → higher variance

We pick the hypothesis that minimises Var(T'_i).

TWO VERSIONS
------------
V1 – Greedy : commit to the best bit at each step (fast, may propagate errors)
V2 – Beam   : keep the top-k candidates (slower, self-correcting)

ENGINEERING IMPROVEMENTS (Part 3)
----------------------------------
Four practical techniques to recover signal buried in OS/Python noise:

  1. GC DISABLE  — Python's garbage collector can inject random multi-ms
                   pauses right in the middle of a tight timing loop.
                   We disable it before each critical section and restore
                   it afterward.

  2. WARM-UP RUNS — CPU branch predictors and L1/L2 caches start cold.
                    The first few calls to any function are systematically
                    slower. We throw away 10 "warm-up" iterations before
                    collecting real measurements.

  3. IQR FILTERING — Context-switch spikes and OS interrupts produce
                     occasional large outliers that inflate variance.
                     Inter-Quartile-Range filtering (keep only values
                     inside [Q1 − f·IQR, Q3 + f·IQR]) removes them
                     without assuming a particular noise distribution.

  4. AMPLIFICATION — Each timed call wraps the operation in a tight
                     inner loop of `amplification` repetitions, so the
                     signal-to-noise ratio scales with √amplification.
"""

import time
import random
import gc
import numpy as np
from scipy import stats

from rsa import RSA


# ══════════════════════════════════════════════════════════════════════════════
#  ROBUST TIMING UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

def iqr_filter(data: list | np.ndarray, factor: float = 1.5) -> np.ndarray:
    """
    Remove outliers using the Inter-Quartile Range (IQR) method.

    Keeps values inside [Q1 − factor·IQR,  Q3 + factor·IQR].
    Falls back to a looser factor of 3.0 if the strict filter would
    discard more than 50 % of the data (protects against degenerate cases).

    Parameters
    ----------
    data   : 1-D array of timing samples
    factor : aggressiveness of the filter (default 1.5, classic Tukey fence)

    Returns
    -------
    np.ndarray of kept values (never empty: returns original if < 4 points)
    """
    data = np.asarray(data, dtype=float)
    if len(data) < 4:
        return data

    q1, q3 = np.percentile(data, [25, 75])
    iqr = q3 - q1

    if iqr == 0:          # all values are identical → nothing to filter
        return data

    lo, hi = q1 - factor * iqr, q3 + factor * iqr
    filtered = data[(data >= lo) & (data <= hi)]

    # Safety valve: if we filtered too aggressively, relax to 3×IQR
    if len(filtered) < len(data) * 0.5:
        lo, hi = q1 - 3.0 * iqr, q3 + 3.0 * iqr
        filtered = data[(data >= lo) & (data <= hi)]

    return filtered


def measure_timed(operation, amplification: int = 200, num_runs: int = 15,
                  warmup: int = 10) -> float:
    """
    Time *operation()* robustly, returning median nanoseconds per call.

    Steps:
      1. Disable Python's garbage collector for the duration.
      2. Run *warmup* calls to prime CPU caches and branch predictor.
      3. For each of *num_runs* runs:
           a. Sleep 1 ms to let the OS settle.
           b. Run the operation *amplification* times in a tight inner loop.
           c. Record elapsed ns, divide by amplification.
      4. Apply IQR filtering to the per-run medians.
      5. Return the median of the filtered values.

    Parameters
    ----------
    operation     : zero-argument callable to time
    amplification : inner-loop repetitions per run (SNR ∝ √amplification)
    num_runs      : outer repetitions (more → more robust median)
    warmup        : throw-away calls before timing starts
    """
    gc_was_enabled = gc.isenabled()
    gc.disable()
    try:
        # ── warm-up ──────────────────────────────────────────────────────────
        for _ in range(warmup):
            operation()

        # ── timed runs ───────────────────────────────────────────────────────
        times = []
        for run in range(num_runs):
            if run > 0:
                time.sleep(0.001)          # let OS interrupt budget reset
            start = time.perf_counter_ns()
            for _ in range(amplification):
                operation()
            elapsed_ns = time.perf_counter_ns() - start
            times.append(elapsed_ns / amplification)

        # ── robust aggregation ───────────────────────────────────────────────
        clean = iqr_filter(times)
        return float(np.median(clean))

    finally:
        if gc_was_enabled:
            gc.enable()


# ══════════════════════════════════════════════════════════════════════════════
#  SERVER
# ══════════════════════════════════════════════════════════════════════════════

class Server:
    """
    Simulates an RSA server that:
      - holds a private key (secret)
      - exposes a public key
      - decrypts messages and leaks wall-clock timing
    """

    def __init__(self, key_size: int = 64):
        """
        Build an RSA key pair of the given bit size.
        key_size = 64 is tiny (demo only); real RSA uses ≥ 2048 bits.
        """
        rsa = RSA()
        n, e, d = rsa.createKeyPair(key_size)
        rsa.setKeys(d, e, n)

        self._rsa             = rsa
        self.public_key: int  = e          # attacker sees this
        self.n: int           = n          # attacker sees this
        self._secret_key: int = d         # attacker must NOT see this (only for verification)

    def decrypt_timed(self, cipher: int,
                      amplification: int = 200,
                      num_runs: int = 15) -> float:
        """
        Decrypt *cipher* and return the robust median time in nanoseconds.

        Improvements over the naive single-shot approach
        ------------------------------------------------
        • GC disabled  → no random GC-pause spikes
        • Warm-up runs → CPU cache / branch-predictor primed
        • Amplification loop → improves SNR by √amplification
        • IQR filter   → OS context-switch outliers removed
        • Median of clean runs → robust central estimate
        """
        return measure_timed(
            lambda: self._rsa.decrypt(cipher),
            amplification=amplification,
            num_runs=num_runs,
        )


# ══════════════════════════════════════════════════════════════════════════════
#  ATTACKER UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

def collect_samples(server: Server, m: int,
                    amplification: int = 200,
                    num_runs: int = 15) -> tuple[list[int], np.ndarray]:
    """
    Send m random plaintexts to the server and record:
      - ys : the plaintext bases y_i  (attacker chose them)
      - Ts : server decryption times  (attacker measured them)

    We encrypt random y to produce valid ciphertexts,
    then measure how long the server takes to decrypt each one.
    """
    ys: list[int] = []
    Ts: list[float] = []

    for i in range(m):
        y      = random.randint(2, server.n - 1)
        cipher = pow(y, server.public_key, server.n)   # attacker encrypts y
        T      = server.decrypt_timed(cipher,
                                      amplification=amplification,
                                      num_runs=num_runs)
        ys.append(cipher)
        Ts.append(T)

        if (i + 1) % max(1, m // 10) == 0:
            print(f"    collected {i+1}/{m} samples …", flush=True)

    return ys, np.array(Ts, dtype=float)


def simulate_partial_time(y: int, x_prefix: int, n_bits: int, n: int,
                           amplification: int = 200,
                           num_runs: int = 15) -> float:
    """
    Locally reproduce the first *n_bits* iterations of fast_exp(y, x_prefix, n)
    and return the robust median time in nanoseconds.

    This gives the attacker an estimate of t(y_i, x_b):
    the portion of the server's work that corresponds to the known prefix.

    Improvements over the single-shot version
    -----------------------------------------
    • GC disabled  → eliminates GC-pause contamination
    • Warm-up runs → caches primed before real measurements
    • Amplification → better SNR for short inner loops
    • IQR filter + median → robust against OS interrupt spikes

    Parameters
    ----------
    y        : plaintext base
    x_prefix : hypothesised exponent prefix (bits 0..n_bits-1)
    n_bits   : how many iterations to simulate (b+1 for bit b)
    n        : RSA modulus
    """
    def _kernel():
        s      = 1
        y_curr = y % n
        x      = x_prefix
        for _ in range(n_bits):
            if x & 1:
                s = (s * y_curr) % n
            y_curr = (y_curr * y_curr) % n
            x >>= 1

    return measure_timed(_kernel, amplification=amplification, num_runs=num_runs)


def corrected_variance(
    Ts: np.ndarray,
    ys: list[int],
    hypothesis: int,
    n_bits: int,
    n: int,
    amplification: int = 200,
    num_runs: int = 15,
) -> float:
    """
    Compute Var(T'_i) where T'_i = T_i - t(y_i, hypothesis).

    Lower variance → hypothesis better explains the server's timing.

    Improvements over the naive version
    ------------------------------------
    • Each partial time is estimated via the robust measure_timed()
      (GC off, warm-up, amplification, IQR filter, median).
    • The final variance is computed on IQR-filtered residuals,
      preventing a few large residual outliers from dominating.
    """
    partial_times = np.array(
        [simulate_partial_time(y, hypothesis, n_bits, n,
                               amplification=amplification,
                               num_runs=num_runs)
         for y in ys],
        dtype=float,
    )

    residuals = Ts - partial_times

    # Apply IQR filter on residuals before computing variance:
    # large outliers (from context switches during baseline collection)
    # artificially inflate the variance and mask the distinguisher signal.
    clean_residuals = iqr_filter(residuals, factor=1.5)

    return float(np.var(clean_residuals))


# ══════════════════════════════════════════════════════════════════════════════
#  SAMPLE SIZE ESTIMATION  (Kocher 1996, §5)
# ══════════════════════════════════════════════════════════════════════════════

def success_probability(j: int, w: int, b: int, c: int) -> float:
    """
    Probability of a correct guess at bit b, given j timing samples.

    Parameters
    ----------
    j : number of timing measurements
    w : total exponent bit-length
    b : current bit position (1-indexed, as in the paper)
    c : number of correctly guessed bits strictly before b
    """
    if b >= w:
        return 1.0
    z = np.sqrt(j * (b - c) / (2 * (w - b)))
    return float(stats.norm.cdf(z))


def required_samples(w: int, target_prob: float, b: int = 1, c: int = 0) -> int:
    """
    Minimum number of timing samples to achieve *target_prob* at bit b.
    """
    if target_prob <= 0 or target_prob >= 1:
        raise ValueError("target_prob must be strictly between 0 and 1")
    z_p = stats.norm.ppf(target_prob)
    j   = z_p ** 2 * 2 * (w - b) / (b - c)
    return int(np.ceil(j))


def print_sample_estimation(w: int, target_prob: float = 0.95) -> int:
    print(f"\n{'═' * 62}")
    print(f"  Sample Size Estimation  (w={w} bits, target P={target_prob:.0%})")
    print(f"{'═' * 62}")

    j_needed = required_samples(w, target_prob, b=1, c=0)
    print(f"  Required samples (worst-case, bit 1) : {j_needed}")
    print()

    print(f"  Per-bit success probability with j={j_needed} samples:")
    print(f"  {'Bit':>5}  {'c (known)':>10}  {'P(correct)':>12}")
    print(f"  {'-'*5}  {'-'*10}  {'-'*12}")

    for b in [1, 2, 5, 10, w // 4, w // 2, w - 2, w - 1]:
        if b >= w:
            continue
        c = b - 1
        p = success_probability(j_needed, w, b, c)
        print(f"  {b:>5}  {c:>10}  {p:>11.1%}")

    print(f"{'═' * 62}")
    return j_needed


# ══════════════════════════════════════════════════════════════════════════════
#  VERSION 1 — SIMPLE GREEDY
# ══════════════════════════════════════════════════════════════════════════════

def attack_v1(server: Server, m: int = 300, n_bits: int = 16,
              amplification: int = 200, num_runs: int = 15) -> int:
    """
    Recover the first *n_bits* bits of the secret exponent, bit by bit.

    For each bit b (LSB first):
      1. Build two hypotheses: current_prefix | (0 << b)  and  | (1 << b)
      2. Compute corrected variance for each
      3. Commit to the bit with lower variance

    Returns the recovered integer (LSB-first bit ordering).
    """
    w = server._secret_key.bit_length()

    print(f"\n{'═' * 62}")
    print(f"  Version 1 — Simple greedy  ({n_bits} bits, {m} samples)")
    print(f"  Exponent length w = {w} bits")
    print(f"  Amplification = {amplification}×,  num_runs = {num_runs}")
    print(f"{'═' * 62}")
    print(f"  {'Bit':>3}  {'Guess':>5}  {'P(theory)':>10}  {'Var(0)':>10}  {'Var(1)':>10}  {'Δ':>10}")
    print(f"  {'-'*3}  {'-'*5}  {'-'*10}  {'-'*10}  {'-'*10}  {'-'*10}")

    print("\n  Collecting baseline timing samples …")
    ys, Ts = collect_samples(server, m, amplification=amplification, num_runs=num_runs)

    # Sanity-check: report signal quality
    cv = np.std(Ts) / np.mean(Ts) * 100
    print(f"  Baseline: mean={np.mean(Ts):.1f} ns, std={np.std(Ts):.1f} ns, CV={cv:.1f}%")
    if cv > 5:
        print("  ⚠  CV > 5 % — high noise; consider more samples or higher amplification.")
    print()

    recovered = 0

    for b in range(n_bits):
        vars_per_bit = {}

        for bit in (0, 1):
            hypothesis        = recovered | (bit << b)
            vars_per_bit[bit] = corrected_variance(
                Ts, ys, hypothesis, b + 1, server.n,
                amplification=amplification, num_runs=num_runs,
            )

        best_bit   = min(vars_per_bit, key=vars_per_bit.get)
        recovered |= (best_bit << b)

        p_theory = success_probability(m, w, b=b + 1, c=b)
        delta    = abs(vars_per_bit[0] - vars_per_bit[1])
        flag     = "✓" if best_bit == ((server._secret_key >> b) & 1) else "✗"
        print(
            f"  {b:>3}  {best_bit:>4}{flag}  {p_theory:>9.1%}  "
            f"{vars_per_bit[0]:>10.2e}  {vars_per_bit[1]:>10.2e}  {delta:>10.2e}"
        )

    expected = server._secret_key & ((1 << n_bits) - 1)
    match    = recovered == expected
    print(f"\n  Recovered : {bin(recovered)}")
    print(f"  Expected  : {bin(expected)}")
    print(f"  Result    : {'✓ CORRECT' if match else '✗ WRONG'}")
    return recovered


# ══════════════════════════════════════════════════════════════════════════════
#  VERSION 2 — BEAM SEARCH (error correction)
# ══════════════════════════════════════════════════════════════════════════════

def attack_v2(
    server: Server,
    m: int = 300,
    n_bits: int = 16,
    beam_width: int = 8,
    amplification: int = 200,
    num_runs: int = 15,
) -> int:
    """
    Recover the first *n_bits* bits using beam search.

    Instead of committing to a single bit at each step, we keep the
    *beam_width* best candidate prefixes ranked by corrected variance.

    This lets the attack recover from an earlier wrong guess:
    a wrong bit creates higher variance and will eventually be pruned,
    while the correct branch keeps climbing to the top.
    """
    print(f"\n{'═' * 62}")
    print(f"  Version 2 — Beam search  ({n_bits} bits, {m} samples, beam={beam_width})")
    print(f"  Amplification = {amplification}×,  num_runs = {num_runs}")
    print(f"{'═' * 62}")

    print("\n  Collecting baseline timing samples …")
    ys, Ts = collect_samples(server, m, amplification=amplification, num_runs=num_runs)
    print()

    candidates: list[tuple[float, int]] = [(0.0, 0)]

    for b in range(n_bits):
        next_candidates: list[tuple[float, int]] = []

        for _, prefix in candidates:
            for bit in (0, 1):
                hypothesis = prefix | (bit << b)
                var        = corrected_variance(
                    Ts, ys, hypothesis, b + 1, server.n,
                    amplification=amplification, num_runs=num_runs,
                )
                next_candidates.append((var, hypothesis))

        next_candidates.sort(key=lambda t: t[0])
        candidates = next_candidates[:beam_width]

        top3 = "  |  ".join(
            f"{bin(h)} ({v:.2e})" for v, h in candidates[:3]
        )
        print(f"  Bit {b:2d}: {top3}")

    best     = candidates[0][1]
    expected = server._secret_key & ((1 << n_bits) - 1)
    match    = best == expected
    print(f"\n  Recovered : {bin(best)}")
    print(f"  Expected  : {bin(expected)}")
    print(f"  Result    : {'✓ CORRECT' if match else '✗ WRONG'}")
    return best


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    random.seed(42)

    # ── Setup ────────────────────────────────────────────────────────────────
    KEY_SIZE      = 512   # total modulus bits  (toy; real RSA ≥ 2048)
    N_BITS        = 16    # how many bits of d to recover
    TARGET_P      = 0.6   # desired per-bit success probability
    AMPLIFICATION = 100   # inner-loop repetitions per timed call
    NUM_RUNS      = 7    # outer repetitions per measurement

    print("  Setting up RSA server …")
    server = Server(key_size=KEY_SIZE)
    print(f"  Public key e = {bin(server.public_key)}")
    print(f"  Modulus    n = {server.n}")
    print(f"  Secret key d = [hidden from attacker]")

    # ── Step 1: estimate how many samples we need BEFORE attacking ───────────
    w = server._secret_key.bit_length()
    M = print_sample_estimation(w, target_prob=TARGET_P)

    # ── Step 2: run both attack versions with the estimated sample count ─────
    recovered_v1 = attack_v1(server, m=M, n_bits=N_BITS,
                             amplification=AMPLIFICATION, num_runs=NUM_RUNS)
    recovered_v2 = attack_v2(server, m=M, n_bits=N_BITS, beam_width=8,
                             amplification=AMPLIFICATION, num_runs=NUM_RUNS)

    # ── Summary ──────────────────────────────────────────────────────────────
    target = server._secret_key & ((1 << N_BITS) - 1)
    print(f"\n{'═' * 62}")
    print(f"  FINAL SUMMARY  ({N_BITS} LSBs of secret exponent d)")
    print(f"  Target   : {bin(target)}")
    print(f"  V1       : {bin(recovered_v1)}  {'✓' if recovered_v1 == target else '✗'}")
    print(f"  V2       : {bin(recovered_v2)}  {'✓' if recovered_v2 == target else '✗'}")
    print(f"{'═' * 62}")
