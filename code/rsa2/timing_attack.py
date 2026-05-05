"""
Kocher's Timing Attack on RSA (1996) — gmpy2 edition
======================================================

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

WHY THE ORIGINAL VARIANCE APPROACH FAILS
-----------------------------------------
The original corrected_variance() called simulate_partial_time(), which
*timed* a Python loop of b iterations locally.  That measurement's
OS-scheduling jitter (≈ 1–10 µs) is the same order as the signal we
want to detect.  Subtracting a noisy t̂_i from a noisy T_i inflates
variance for BOTH hypotheses equally — the correct/wrong difference
disappears.

FIX: CORRELATION INSTEAD OF VARIANCE
--------------------------------------
Instead of subtracting a noisy estimate, we ask:
  "Does the proxy for step b move together with T_i?"

  proxy_i  = Hamming weight of  s_b(y_i) × base_b(y_i)  [pre-reduction]

  • When bit b = 1 and prefix is correct:
      server actually computes  t_mod(s_b × base_b, n)
      → its timing is data-dependent on (s_b, base_b)
      → corr(proxy_i, T_i) > 0   ✓

  • When bit b = 0 or prefix is wrong:
      the product is never computed by the server
      → proxy and T_i are independent → corr ≈ 0   ✗

The proxy is PURELY ARITHMETIC — no local timing, zero added noise.

THREE ATTACK VERSIONS
---------------------
V1 – Greedy  : commit to the best bit at each step (fast, may propagate errors)
V2 – Beam    : keep top-k candidates (self-correcting)
V3 – Correlation (NEW): use Pearson r instead of variance — the fix
"""

import time
import random
import numpy as np
from scipy import stats
import gmpy2
from gmpy2 import mpz

from rsa import RSA


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
        rsa = RSA()
        n, e, d = rsa.createKeyPair(key_size)
        rsa.setKeys(d, e, n)

        self._rsa             = rsa
        self.public_key: int  = e
        self.n: int           = n
        self._secret_key: int = d

    def decrypt_timed(self, cipher: int, repeat: int = 15) -> float:
        """
        Decrypt *cipher* and return the MINIMUM elapsed time in nanoseconds.

        WHY MIN, NOT MEDIAN?
        --------------------
        For CPU timing, the *minimum* over many runs is the best estimator
        of true execution time.  Outliers are always HIGH (OS preemption,
        cache misses); the minimum is closest to the uninterrupted cost.
        Median is more robust to extreme outliers but converges more slowly
        to the true time — min is standard practice in micro-benchmarking.
        """
        times = []
        for _ in range(repeat):
            start = time.perf_counter_ns()
            self._rsa.decrypt(cipher)
            times.append(time.perf_counter_ns() - start)
        return float(np.min(times))


# ══════════════════════════════════════════════════════════════════════════════
#  ATTACKER UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

def collect_samples(server: Server, m: int, repeat: int = 15) -> tuple[list[int], np.ndarray]:
    """
    Send *m* random ciphertexts to the server and record:
      - ys : the ciphertexts (chosen by attacker)
      - Ts : server decryption times in nanoseconds
    """
    ys: list[int] = []
    Ts: list[float] = []

    pub = mpz(server.public_key)
    n   = mpz(server.n)

    for _ in range(m):
        y      = mpz(random.randint(2, int(server.n) - 1))
        cipher = int(gmpy2.powmod(y, pub, n))
        T      = server.decrypt_timed(cipher, repeat)
        ys.append(cipher)
        Ts.append(T)

    return ys, np.array(Ts, dtype=float)


# ──────────────────────────────────────────────────────────────────────────────
#  CORE: deterministic state simulation (no timing noise)
# ──────────────────────────────────────────────────────────────────────────────

def simulate_state_only(y: int, x_prefix: int, n_bits: int, n: int) -> tuple[mpz, mpz]:
    """
    Run the first *n_bits* iterations of fast_exp(y, x_prefix, n) and return
    the intermediate state (s, y_curr) WITHOUT measuring time.

    WHY NOT simulate_partial_time?
    ───────────────────────────────
    The old function timed a Python loop of b iterations.  That loop's
    OS-scheduling jitter (≈ 1–10 µs) equals or exceeds the per-bit
    timing signal (≈ 0.1–1 µs for a single GMP multiplication).
    Subtracting that noisy estimate from T_i amplifies — not reduces —
    the variance, making it impossible to distinguish the two hypotheses.

    This function is purely arithmetic: no clock calls, zero added noise.
    The state (s, y_curr) is used to build a *deterministic* proxy.
    """
    s      = mpz(1)
    y_curr = mpz(y) % mpz(n)
    n_mpz  = mpz(n)
    x      = int(x_prefix)

    for _ in range(n_bits):
        if x & 1:
            s = gmpy2.t_mod(s * y_curr, n_mpz)
        y_curr = gmpy2.t_mod(y_curr * y_curr, n_mpz)
        x >>= 1

    return s, y_curr


def mult_proxy(s: mpz, y_curr: mpz) -> float:
    """
    Deterministic proxy for the cost of  t_mod(s * y_curr, n).

    Uses the Hamming weight of the full pre-reduction product  s × y_curr
    (a ~1024-bit integer for 512-bit operands).

    WHY THIS WORKS
    ──────────────
    GMP's t_mod internally performs multi-precision division.  The division
    algorithm subtracts multiples of the divisor from the dividend, and the
    number of subtraction steps — plus carry propagation — is
    data-dependent.  The Hamming weight of the product (number of 1-bits)
    serves as a fingerprint of the operand bit patterns that correlates
    with those data-dependent branches.

    For 512-bit operands the Hamming weight of the ~1024-bit product has
    mean ≈ 512 and std ≈ 16.  That modest variation is enough for Pearson
    correlation to detect the signal given ~1 000 samples.

    No timing is involved → zero noise added.
    """
    product = int(s) * int(y_curr)           # full ~1024-bit product, no reduction
    return float(bin(product).count('1'))    # Hamming weight


def correlation_discriminant(
    Ts: np.ndarray,
    ys: list[int],
    prefix: int,
    b: int,
    n: int,
) -> float:
    """
    Pearson r between mult_proxy_i and T_i.

    *prefix* holds the known bits 0 … b-1.  We simulate b iterations
    (the prefix portion) to reach state (s_b, base_b), then compute
    mult_proxy(s_b, base_b).

    If the prefix is correct AND bit b = 1 in the secret key:
      • The server actually computes  s_b × base_b mod n  at step b.
      • proxy_i varies with y_i (different (s_b, base_b) per input).
      • The server's timing at step b correlates with proxy_i.
      • r > 0  ✓

    If bit b = 0 or the prefix is wrong:
      • The product is never computed, or the state is mis-simulated.
      • proxy_i and T_i are uncorrelated → r ≈ 0  ✗
    """
    proxies = []
    for y in ys:
        s, base = simulate_state_only(y, prefix, b, n)
        proxies.append(mult_proxy(s, base))

    proxies_arr = np.array(proxies, dtype=float)
    if np.std(proxies_arr) < 1e-10:
        return 0.0
    return float(np.corrcoef(proxies_arr, Ts)[0, 1])


# ══════════════════════════════════════════════════════════════════════════════
#  SAMPLE SIZE ESTIMATION  (Kocher 1996, §5)
# ══════════════════════════════════════════════════════════════════════════════

def success_probability(j: int, w: int, b: int, c: int) -> float:
    """
    Probability of a correct guess at bit b, given j timing samples.
    """
    if b >= w:
        return 1.0
    z = np.sqrt(j * (b - c) / (2 * (w - b)))
    return float(stats.norm.cdf(z))


def required_samples(w: int, target_prob: float, b: int = 1, c: int = 0) -> int:
    """Minimum timing samples to achieve *target_prob* at bit b."""
    if not (0 < target_prob < 1):
        raise ValueError("target_prob must be strictly between 0 and 1")
    z_p = stats.norm.ppf(target_prob)
    j   = z_p ** 2 * 2 * (w - b) / (b - c)
    return int(np.ceil(j))


def print_sample_estimation(w: int, target_prob: float = 0.95) -> int:
    print(f"\n{'═' * 62}")
    print(f"  Sample Size Estimation  (w={w} bits, target P={target_prob:.0%})")
    print(f"{'═' * 62}")

    j_needed = required_samples(w, target_prob, b=1, c=0)
    print(f"  Required samples (worst-case, bit 1) : {j_needed}\n")

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
#  VERSION 1 — SIMPLE GREEDY (kept for reference, uses old variance method)
# ══════════════════════════════════════════════════════════════════════════════

def simulate_partial_time(y: int, x_prefix: int, n_bits: int, n: int) -> float:
    """
    [LEGACY — kept for V1/V2 comparison]
    Locally reproduce the first *n_bits* iterations and return wall-clock time.

    NOTE: This is the function whose noise breaks V1/V2.  The timing of
    b Python-loop iterations has jitter ≥ the GMP multiplication signal,
    so the 'corrected' residual T_i - t̂_i is noisier than T_i itself.
    """
    s      = mpz(1)
    y_curr = mpz(y) % mpz(n)
    n_mpz  = mpz(n)
    x      = int(x_prefix)

    start = time.perf_counter_ns()
    for _ in range(n_bits):
        if x & 1:
            s = gmpy2.t_mod(s * y_curr, n_mpz)
        y_curr = gmpy2.t_mod(y_curr * y_curr, n_mpz)
        x >>= 1
    return float(time.perf_counter_ns() - start)


def corrected_variance(
    Ts: np.ndarray,
    ys: list[int],
    hypothesis: int,
    n_bits: int,
    n: int,
    repeat: int = 5
) -> float:
    """[LEGACY] Var(T_i - t̂_i) — broken by simulation noise, kept for comparison."""
    partial_times = []
    for y in ys:
        tmp = [simulate_partial_time(y, hypothesis, n_bits, n) for _ in range(repeat)]
        partial_times.append(float(np.mean(tmp)))

    residuals = Ts - np.array(partial_times, dtype=float)
    return float(np.var(residuals))


def attack_v1(server: Server, m: int = 300, n_bits: int = 16, repeat: int = 5) -> int:
    """
    [LEGACY — Greedy, variance-based]
    Kept so you can compare it directly against V3.
    """
    w = server._secret_key.bit_length()

    print(f"\n{'═' * 62}")
    print(f"  Version 1 — Simple greedy  ({n_bits} bits, {m} samples)")
    print(f"  Exponent length w = {w} bits")
    print(f"{'═' * 62}")
    print(f"  {'Bit':>3}  {'Guess':>5}  {'P(theory)':>10}  {'Var(0)':>10}  {'Var(1)':>10}  {'Δ':>10}")
    print(f"  {'-'*3}  {'-'*5}  {'-'*10}  {'-'*10}  {'-'*10}  {'-'*10}")

    ys, Ts    = collect_samples(server, m)
    recovered = 0

    for b in range(n_bits):
        vars_per_bit = {}
        for bit in (0, 1):
            hyp              = recovered | (bit << b)
            vars_per_bit[bit] = corrected_variance(Ts, ys, hyp, b + 1, server.n, repeat)

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
#  VERSION 2 — BEAM SEARCH (variance, legacy)
# ══════════════════════════════════════════════════════════════════════════════

def attack_v2(
    server: Server,
    m: int = 300,
    n_bits: int = 16,
    beam_width: int = 8,
    repeat: int = 5
) -> int:
    """
    [LEGACY — Beam search, variance-based]
    Kept so you can compare it directly against V3.
    """
    print(f"\n{'═' * 62}")
    print(f"  Version 2 — Beam search  ({n_bits} bits, {m} samples, beam={beam_width})")
    print(f"{'═' * 62}")

    ys, Ts     = collect_samples(server, m)
    candidates: list[tuple[float, int]] = [(0.0, 0)]

    for b in range(n_bits):
        next_candidates: list[tuple[float, int]] = []
        for _, prefix in candidates:
            for bit in (0, 1):
                hyp = prefix | (bit << b)
                var = corrected_variance(Ts, ys, hyp, b + 1, server.n, repeat)
                next_candidates.append((var, hyp))

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
#  VERSION 3 — CORRELATION (NEW — the fix)
# ══════════════════════════════════════════════════════════════════════════════

def attack_v3_correlation(
    server: Server,
    m: int = 300,
    n_bits: int = 16,
) -> int:
    """
    Recover the first *n_bits* bits using Pearson correlation.

    ALGORITHM
    ─────────
    For each bit b (LSB first), knowing prefix = bits 0..b-1:

      1. For every ciphertext y_i:
         a. Simulate b iterations of fast_exp with the known prefix
            (DETERMINISTIC — no timing) → get state (s_b, base_b).
         b. proxy_i = Hamming weight of (s_b × base_b)  [pre-reduction].

      2. r = Pearson(proxy_i, T_i)

      3. bit b = 1 if r > 0, else bit b = 0.

    WHY r > 0 → bit = 1
    ────────────────────
    If bit b = 1, the server computes  t_mod(s_b(y_i) × base_b(y_i), n)
    at iteration b.  The time for that operation is data-dependent on
    (s_b, base_b) — GMP's multi-precision division has data-dependent
    carry chains.  proxy_i approximates that dependence, so  r > 0.

    If bit b = 0, the server never computes that product, so T_i has no
    systematic dependence on proxy_i, and  r ≈ 0.

    WHY BETTER THAN V1/V2
    ──────────────────────
    V1/V2 subtract a *locally timed* partial computation from T_i.
    That local timing has OS-jitter ≈ 1–10 µs, which equals or exceeds
    the GMP per-bit signal.  The subtraction amplifies rather than
    reduces noise, making the two hypotheses indistinguishable.

    V3 never subtracts anything.  It only checks co-movement of a
    zero-noise deterministic proxy with T_i.
    """
    w = server._secret_key.bit_length()

    print(f"\n{'═' * 62}")
    print(f"  Version 3 — Correlation  ({n_bits} bits, {m} samples)")
    print(f"  Exponent length w = {w} bits")
    print(f"{'═' * 62}")
    print(f"  {'Bit':>3}  {'Guess':>5}  {'r':>8}  {'Actual':>6}  {'Signal'}")
    print(f"  {'-'*3}  {'-'*5}  {'-'*8}  {'-'*6}  {'-'*6}")

    ys, Ts    = collect_samples(server, m, repeat=15)
    recovered = 0

    for b in range(n_bits):
        r        = correlation_discriminant(Ts, ys, recovered, b, server.n)
        best_bit = 1 if r > 0 else 0
        recovered |= (best_bit << b)

        actual   = (server._secret_key >> b) & 1
        flag     = "✓" if best_bit == actual else "✗"
        signal   = "strong" if abs(r) > 0.05 else ("weak" if abs(r) > 0.02 else "noise")
        print(f"  {b:>3}  {best_bit:>4}{flag}  {r:>8.4f}  {actual:>6}  {signal}")

    expected = server._secret_key & ((1 << n_bits) - 1)
    match    = recovered == expected
    print(f"\n  Recovered : {bin(recovered)}")
    print(f"  Expected  : {bin(expected)}")
    print(f"  Result    : {'✓ CORRECT' if match else '✗ WRONG'}")
    return recovered


# ══════════════════════════════════════════════════════════════════════════════
#  VERSION 4 — BEAM SEARCH + CORRELATION (error-correcting, new)
# ══════════════════════════════════════════════════════════════════════════════

def attack_v4_beam_correlation(
    server: Server,
    m: int = 300,
    n_bits: int = 16,
    beam_width: int = 8,
) -> int:
    """
    Beam search using Pearson r as the discriminant (self-correcting + noise-robust).

    Instead of pruning by variance, candidates are ranked by cumulative
    correlation score: at each step b, we extend every candidate with
    both bit=0 and bit=1 and score them by the signed correlation r:

        score for bit=1 → +r   (positive r means 1 explains T_i)
        score for bit=0 → −r   (negative r means 0 explains T_i)

    We keep the top *beam_width* candidates by total accumulated score.
    """
    print(f"\n{'═' * 62}")
    print(f"  Version 4 — Beam+Correlation  ({n_bits} bits, {m} samples, beam={beam_width})")
    print(f"{'═' * 62}")

    ys, Ts = collect_samples(server, m, repeat=15)
    # candidates: list of (cumulative_score, prefix_int)
    candidates: list[tuple[float, int]] = [(0.0, 0)]

    for b in range(n_bits):
        next_candidates: list[tuple[float, int]] = []
        for cum_score, prefix in candidates:
            r = correlation_discriminant(Ts, ys, prefix, b, server.n)
            for bit in (0, 1):
                # Signed contribution: +r rewards bit=1, -r rewards bit=0
                bit_score = r if bit == 1 else -r
                hyp       = prefix | (bit << b)
                next_candidates.append((cum_score + bit_score, hyp))

        next_candidates.sort(key=lambda t: t[0], reverse=True)
        candidates = next_candidates[:beam_width]

        top3 = "  |  ".join(
            f"{bin(h)}({s:+.3f})" for s, h in candidates[:3]
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

    KEY_SIZE = 512   # total modulus bits (tiny for demo; real RSA uses ≥ 2048)
    N_BITS   = 16    # how many bits of d to recover
    TARGET_P = 0.999 # desired per-bit success probability

    print("  Setting up RSA server …")
    server = Server(key_size=KEY_SIZE)
    print(f"  Public key e = {bin(server.public_key)}")
    print(f"  Modulus    n = {server.n}")
    print(f"  Secret key d = [hidden from attacker]")

    w = server._secret_key.bit_length()
    M = print_sample_estimation(w, target_prob=TARGET_P)

    # ── Run all four versions for comparison ──────────────────────────────────
    recovered_v1 = attack_v1(server, m=M, n_bits=N_BITS, repeat=5)
    recovered_v2 = attack_v2(server, m=M, n_bits=N_BITS, beam_width=8, repeat=5)
    recovered_v3 = attack_v3_correlation(server, m=M, n_bits=N_BITS)
    recovered_v4 = attack_v4_beam_correlation(server, m=M, n_bits=N_BITS, beam_width=8)

    target = server._secret_key & ((1 << N_BITS) - 1)
    print(f"\n{'═' * 62}")
    print(f"  FINAL SUMMARY  ({N_BITS} LSBs of secret exponent d)")
    print(f"  Target   : {bin(target)}")
    print(f"  V1       : {bin(recovered_v1)}  {'✓' if recovered_v1 == target else '✗'}")
    print(f"  V2       : {bin(recovered_v2)}  {'✓' if recovered_v2 == target else '✗'}")
    print(f"  V3 (corr): {bin(recovered_v3)}  {'✓' if recovered_v3 == target else '✗'}")
    print(f"  V4 (beam+corr): {bin(recovered_v4)}  {'✓' if recovered_v4 == target else '✗'}")
    print(f"{'═' * 62}")
