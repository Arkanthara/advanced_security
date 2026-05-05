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

When bit b = 1, the server does one extra modular multiplication whose
duration depends on the actual operand values at that step.

WHY WALL-CLOCK TIMING DOES NOT WORK IN PYTHON
----------------------------------------------
The naive approach (time.perf_counter_ns() around the server call, then again
locally for the partial simulation) fails because:

  • Both measurements are dominated by Python interpreter overhead and OS
    scheduling jitter (~100-1000 ns), which is UNCORRELATED between the two
    independent calls.
  • Subtracting t_local from T_server does NOT cancel noise — it doubles it.
  • For small RSA keys, each multiplication takes < 1 µs, so the modular
    arithmetic timing never rises above the noise floor.

THE FIX: SYNTHETIC TIMING
--------------------------
Both the server and the attacker's local simulation use the SAME deterministic
timing model:

    time(a, b, n) = MULT_BASE + MULT_SCALE × hamming_weight(a·b mod n)

On real hardware, modular multiplication time varies with operand bit patterns
(carry propagation, Karatsuba sub-problems, etc.). Hamming weight is a simple
but valid proxy for this effect.

Because the attacker knows the exact values of s and y for the known bits,
their local estimate t(y_i, hypothesis) is EXACT for those steps — no extra
noise introduced. The only residual in T'_i = T_i − t(y_i, h) is the
Gaussian measurement noise and the unknown-bits contribution.

TWO BUGS FIXED (vs previous version)
--------------------------------------
1. e=65537 instead of random 512-bit e
   The RSA class was generating e ~ 2^512, making d ~ 2^512 too (wrong).
   With e=65537, d = e^{-1} mod φ(n) is properly bounded to ≤ φ(n) ≈ n.
   This also fixes w (exponent bit-length) being reported as 507.

2. Synthetic timing model instead of wall-clock timing
   See the explanation above.

STATISTICAL STRATEGY (per bit b, knowing bits 0..b-1)
------------------------------------------------------
Let T_i   = total server time for input y_i (synthetic model + noise)
    t_j   = time for iteration j (squaring + optional extra mult if bit j = 1)

We hypothesize bit b and simulate the first b+1 iterations locally:
    T'_i = T_i − t(y_i, hypothesis)

• Hypothesis CORRECT  → T'_i = noise + Σ_{j=b+1}^{w-1} t_j   → LOW  variance
• Hypothesis WRONG    → residual contains ± extra mult at step b → HIGH variance
  (extra mult time varies across y_i because operand s_b differs per input)

TWO VERSIONS
------------
V1 – Greedy : commit to the best bit at each step (fast, may propagate errors)
V2 – Beam   : keep the top-k candidates (slower, self-correcting)

SAMPLE SIZE ESTIMATION  (Kocher 1996, §5)
------------------------------------------
At bit position b (1-indexed), knowing the first c bits correctly, the
probability of a correct guess with j timing samples is:

     P = Φ( √( j·(b−c) / (2·(w−b)) ) )

where Φ is the standard normal CDF and w is the total exponent bit-length.

Inverting for j:   j = [ Φ⁻¹(P) ]² · 2·(w−b) / (b−c)

For the greedy attack (c = b−1 at each step): b−c = 1 always.
The hardest bit is always the first one (b=1), where w−b is maximal.
"""

import random
import numpy as np
from scipy import stats
from rsa import RSA


# ══════════════════════════════════════════════════════════════════════════════
#  SYNTHETIC TIMING MODEL
# ══════════════════════════════════════════════════════════════════════════════
#
#  On real hardware (Kocher 1996), each (a·b mod n) computation takes slightly
#  different time depending on the actual bit patterns of a and b (carry chains,
#  Karatsuba sub-problem sizes, cache effects, etc.).
#
#  We model this as:
#      time(a, b, n) = MULT_BASE + MULT_SCALE × hamming_weight(a·b mod n)
#
#  The Hamming weight of the product varies across different inputs, creating
#  the statistical signal the attack exploits. NOISE_STD represents OS jitter.
#
MULT_BASE  = 200    # ns: base time for any multiplication
MULT_SCALE = 15     # ns: extra time per Hamming-weight unit of result
NOISE_STD  = 800    # ns: Gaussian measurement noise (OS jitter, cache effects)


def mult_time(a: int, b: int, n: int) -> float:
    """
    Synthetic, operand-dependent timing for (a·b mod n), in nanoseconds.
    Both server and attacker use this exact same function — that is the key.
    """
    hw = bin((a * b) % n).count('1')
    return MULT_BASE + MULT_SCALE * hw


# ══════════════════════════════════════════════════════════════════════════════
#  SERVER
# ══════════════════════════════════════════════════════════════════════════════

class Server:
    """
    RSA server: exposes public key and timed decryption.

    Timing is SYNTHETIC (deterministic operand-dependent model + Gaussian noise),
    not wall-clock. This correctly simulates what a real hardware timing oracle
    leaks, without being swamped by Python interpreter overhead.
    """

    def __init__(self, key_size: int = 64):
        """
        Build an RSA key pair of the given bit size.
        Uses e=65537 (standard Fermat prime) so the private key d is properly
        bounded: d < φ(n) < n ≈ 2^key_size, giving a sensible bit-length w.
        """
        rsa  = RSA()
        half = key_size // 2
        p    = rsa.primary_nb_generator(2**(half-1), 2**half)
        q    = rsa.primary_nb_generator(2**(half-1), 2**half)

        # e=65537 ensures gcd(e, φ(n)) = 1 for all practical prime pairs,
        # and keeps d bounded to ≈ key_size bits.
        # FIX: previous code used random 512-bit e, making d ~ 2^512 (wrong).
        n, e, d = rsa.key_generator(p, q, e=65537)
        rsa.setKeys(d, e, n)

        self._rsa        = rsa
        self.public_key  = e           # attacker sees this
        self.n           = n           # attacker sees this
        self._secret_key = d           # attacker must NOT see this (only for verification)

    def decrypt_timed(self, cipher: int) -> float:
        """
        Decrypt cipher and return SYNTHETIC timing (ns).

        Follows fast_exp exactly. Each multiplication's reported time depends
        on its actual operand values, mirroring real hardware behavior.
        A single Gaussian noise term accounts for measurement uncertainty.
        """
        s     = 1
        y     = cipher % self.n
        x     = self._secret_key
        total = 0.0

        while x > 0:
            if x & 1:
                total += mult_time(s, y, self.n)    # operand-dependent extra mult
                s = (s * y) % self.n
            total += mult_time(y, y, self.n)        # squaring: always performed
            y = (y * y) % self.n
            x >>= 1

        return total + random.gauss(0, NOISE_STD)   # measurement noise


# ══════════════════════════════════════════════════════════════════════════════
#  ATTACKER UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

def collect_samples(server: Server, m: int) -> tuple[list[int], np.ndarray]:
    """
    Query the server m times with random ciphertexts.
    Returns (y_list, T_array) where T_i is the server's timed response.
    """
    ys: list[int] = []
    Ts: list[int] = []

    for _ in range(m):
        y      = random.randint(2, server.n - 1)
        cipher = pow(y, server.public_key, server.n)
        T      = server.decrypt_timed(cipher)
        ys.append(cipher)
        Ts.append(T)

    return ys, np.array(Ts, dtype=float)


def simulate_partial_time(y: int, x_prefix: int, n_bits: int, n: int) -> float:
    """
    Estimate the server's time for the first n_bits iterations using the
    SAME synthetic timing model as the server.

    Because the attacker knows x_prefix exactly and tracks s and y step by
    step, this estimate is EXACT for those n_bits iterations — no additional
    noise is introduced. The residual T'_i = T_i − this contains only:
      • Gaussian measurement noise (same magnitude for both hypotheses)
      • The unknown-bits contribution (bits b+1..w-1)

    Parameters
    ----------
    y        : original plaintext base (attacker chose it)
    x_prefix : hypothesised exponent prefix (bits 0..n_bits-1)
    n_bits   : number of iterations to simulate (b+1 for bit b)
    n        : RSA modulus
    """
    s      = 1
    y_curr = y % n
    x      = x_prefix
    total  = 0.0

    for _ in range(n_bits):
        if x & 1:
            total += mult_time(s, y_curr, n)    # exact same formula as server
            s = (s * y_curr) % n
        total += mult_time(y_curr, y_curr, n)   # squaring: always
        y_curr = (y_curr * y_curr) % n
        x >>= 1

    return total


def corrected_variance(
    Ts: np.ndarray,
    ys: list[int],
    hypothesis: int,
    n_bits: int,
    n: int,
) -> float:
    """
    Compute Var(T'_i) where T'_i = T_i − t(y_i, hypothesis).

    Lower variance → hypothesis better explains the server's timing.
    The correct hypothesis perfectly cancels the known-bits contribution,
    leaving only the unknown-bits residual plus Gaussian noise.
    """
    partial = np.array(
        [simulate_partial_time(y, hypothesis, n_bits, n) for y in ys]
    )
    return float(np.var(Ts - partial))


# ══════════════════════════════════════════════════════════════════════════════
#  SAMPLE SIZE ESTIMATION  (Kocher 1996, §5)
# ══════════════════════════════════════════════════════════════════════════════

def success_probability(j: int, w: int, b: int, c: int) -> float:
    """
    Probability of a correct guess at bit b given j timing samples.

    P = Φ( √( j·(b−c) / (2·(w−b)) ) )

    Parameters
    ----------
    j : number of timing measurements
    w : total exponent bit-length
    b : current bit position (1-indexed, as in the paper)
    c : correctly guessed bits strictly before b (greedy: c = b−1)
    """
    if b >= w:
        return 1.0
    z = np.sqrt(j * (b - c) / (2 * (w - b)))
    return float(stats.norm.cdf(z))


def required_samples(w: int, target_prob: float, b: int = 1, c: int = 0) -> int:
    """
    Minimum samples to achieve target_prob at bit b.

    j = [ Φ⁻¹(P) ]² · 2·(w−b) / (b−c)

    Default b=1, c=0 gives the worst-case (hardest bit = first bit).
    """
    if not (0 < target_prob < 1):
        raise ValueError("target_prob must be strictly between 0 and 1")
    z_p = stats.norm.ppf(target_prob)
    return int(np.ceil(z_p**2 * 2 * (w - b) / (b - c)))


def print_sample_estimation(w: int, target_prob: float = 0.95) -> int:
    """
    Print the sample-size analysis and return the required sample count.

    Shows the worst-case requirement (first bit) and how per-bit probability
    improves as more bits become known (greedy scenario: c = b−1).
    """
    print(f"\n{'═' * 62}")
    print(f"  Sample Size Estimation  (w={w} bits, target P={target_prob:.0%})")
    print(f"{'═' * 62}")

    j_needed = required_samples(w, target_prob, b=1, c=0)
    print(f"  Required samples (worst-case, bit 1) : {j_needed}")
    print()
    print(f"  Per-bit success probability with j={j_needed} samples:")
    print(f"  {'Bit':>5}  {'c (known)':>10}  {'P(correct)':>12}")
    print(f"  {'-'*5}  {'-'*10}  {'-'*12}")

    for b in sorted({1, 2, 5, 10, w//4, w//2, w-2, w-1}):
        if b < 1 or b >= w:
            continue
        c = b - 1    # greedy: all previous bits assumed correct
        p = success_probability(j_needed, w, b, c)
        print(f"  {b:>5}  {c:>10}  {p:>11.1%}")

    print(f"{'═' * 62}")
    return j_needed


# ══════════════════════════════════════════════════════════════════════════════
#  VERSION 1 — SIMPLE GREEDY
# ══════════════════════════════════════════════════════════════════════════════

def attack_v1(server: Server, m: int, n_bits: int) -> int:
    """
    Recover the first n_bits bits of the secret exponent, one bit at a time.

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
    print(f"{'═' * 62}")
    print(f"  {'Bit':>3}  {'Guess':>5}  {'P(theory)':>10}  {'Var(0)':>10}  {'Var(1)':>10}  {'Δ':>10}")
    print(f"  {'-'*3}  {'-'*5}  {'-'*10}  {'-'*10}  {'-'*10}  {'-'*10}")

    ys, Ts    = collect_samples(server, m)
    recovered = 0

    for b in range(n_bits):
        vars_per_bit = {}
        for bit in (0, 1):
            hypothesis        = recovered | (bit << b)
            vars_per_bit[bit] = corrected_variance(Ts, ys, hypothesis, b + 1, server.n)

        best_bit   = min(vars_per_bit, key=vars_per_bit.get)
        recovered |= (best_bit << b)

        # Paper uses 1-indexed b; greedy assumes c = b (all previous correct)
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

def attack_v2(server: Server, m: int, n_bits: int, beam_width: int = 8) -> int:
    """
    Recover the first n_bits bits using beam search.

    Instead of committing to a single bit at each step, keep the beam_width
    best candidate prefixes ranked by corrected variance (lower = better).

    A wrong bit creates higher variance and gets pruned over subsequent steps,
    while the correct branch stays at the top.

    Returns the best candidate (lowest cumulative variance).
    """
    print(f"\n{'═' * 62}")
    print(f"  Version 2 — Beam search  ({n_bits} bits, {m} samples, beam={beam_width})")
    print(f"{'═' * 62}")

    ys, Ts = collect_samples(server, m)

    # Each candidate: (variance_score, prefix_value)
    candidates: list[tuple[float, int]] = [(0.0, 0)]

    for b in range(n_bits):
        next_candidates: list[tuple[float, int]] = []
        for _, prefix in candidates:
            for bit in (0, 1):
                hypothesis = prefix | (bit << b)
                var        = corrected_variance(Ts, ys, hypothesis, b + 1, server.n)
                next_candidates.append((var, hypothesis))

        next_candidates.sort(key=lambda t: t[0])
        candidates = next_candidates[:beam_width]

        top3 = "  |  ".join(f"{bin(h)} ({v:.2e})" for v, h in candidates[:3])
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

    KEY_SIZE = 2048    # total modulus bits (toy size; real RSA ≥ 2048)
    N_BITS   = 32    # how many bits of d to recover
    TARGET_P = 0.999  # desired per-bit success probability

    print("  Setting up RSA server …")
    server = Server(key_size=KEY_SIZE)
    print(f"  Public key  e = {server.public_key}  ({server.public_key.bit_length()} bits)")
    print(f"  Modulus     n = {server.n}  ({server.n.bit_length()} bits)")
    print(f"  Secret key  d = [hidden]  ({server._secret_key.bit_length()} bits)")

    # ── Step 1: estimate required samples from theory ─────────────────────────
    w = server._secret_key.bit_length()
    M = print_sample_estimation(w, target_prob=TARGET_P)

    # ── Step 2: run both attacks ───────────────────────────────────────────────
    recovered_v1 = attack_v1(server, m=M, n_bits=N_BITS)
    recovered_v2 = attack_v2(server, m=M, n_bits=N_BITS, beam_width=8)

    # ── Summary ───────────────────────────────────────────────────────────────
    target = server._secret_key & ((1 << N_BITS) - 1)
    print(f"\n{'═' * 62}")
    print(f"  FINAL SUMMARY  ({N_BITS} LSBs of secret exponent d)")
    print(f"  Target   : {bin(target)}")
    print(f"  V1       : {bin(recovered_v1)}  {'✓' if recovered_v1 == target else '✗'}")
    print(f"  V2       : {bin(recovered_v2)}  {'✓' if recovered_v2 == target else '✗'}")
    print(f"{'═' * 62}")
