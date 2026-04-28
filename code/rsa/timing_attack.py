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
"""

import time
import random
import numpy as np
from scipy import stats

# Import the provided RSA class (assumed to be in rsa.py)
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
        """
        Build an RSA key pair of the given bit size.
        key_size = 64 is tiny (demo only); real RSA uses ≥ 2048 bits.
        """
        rsa = RSA()
        n, e, d = rsa.createKeyPair(key_size)
        rsa.setKeys(d, e, n)

        self._rsa            = rsa
        self.public_key: int = e          # attacker sees this
        self.n: int          = n          # attacker sees this
        self._secret_key: int = d         # attacker must NOT see this (only for verification)

    def decrypt_timed(self, cipher: int) -> int:
        """
        Decrypt *cipher* and return elapsed time in nanoseconds.
        This is the only information the attacker is allowed to observe.
        """
        start = time.perf_counter_ns()
        self._rsa.decrypt(cipher)
        return time.perf_counter_ns() - start


# ══════════════════════════════════════════════════════════════════════════════
#  ATTACKER UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

def collect_samples(server: Server, m: int) -> tuple[list[int], np.ndarray]:
    """
    Send m random plaintexts to the server and record:
      - ys : the plaintext bases y_i  (attacker chose them)
      - Ts : server decryption times  (attacker measured them)

    We encrypt random y to produce valid ciphertexts,
    then measure how long the server takes to decrypt each one.
    """
    ys: list[int] = []
    Ts: list[int] = []

    for _ in range(m):
        y      = random.randint(2, server.n - 1)
        cipher = pow(y, server.public_key, server.n)   # attacker encrypts y
        T      = server.decrypt_timed(cipher)           # server decrypts, leaks time
        ys.append(y)
        Ts.append(T)

    return ys, np.array(Ts, dtype=float)


def simulate_partial_time(y: int, x_prefix: int, n_bits: int, n: int) -> float:
    """
    Locally reproduce the first *n_bits* iterations of fast_exp(y, x_prefix, n)
    and return the wall-clock time in nanoseconds.

    This gives the attacker an estimate of t(y_i, x_b):
    the portion of the server's work that corresponds to the known prefix.

    Parameters
    ----------
    y        : plaintext base
    x_prefix : hypothesised exponent prefix (bits 0..n_bits-1)
    n_bits   : how many iterations to simulate (b+1 for bit b)
    n        : RSA modulus
    """
    s      = 1
    y_curr = y % n
    x      = x_prefix
    start  = time.perf_counter_ns()

    for _ in range(n_bits):
        if x & 1:                        # bit = 1 → extra multiplication
            s = (s * y_curr) % n
        y_curr = (y_curr * y_curr) % n  # always squaring
        x >>= 1

    return float(time.perf_counter_ns() - start)


def corrected_variance(
    Ts: np.ndarray,
    ys: list[int],
    hypothesis: int,
    n_bits: int,
    n: int,
) -> float:
    """
    Compute Var(T'_i) where T'_i = T_i - t(y_i, hypothesis).

    Lower variance → hypothesis better explains the server's timing.
    """
    partial_times = np.array(
        [simulate_partial_time(y, hypothesis, n_bits, n) for y in ys]
    )
    return float(np.var(Ts - partial_times))


# ══════════════════════════════════════════════════════════════════════════════
#  SAMPLE SIZE ESTIMATION  (Kocher 1996, §5)
# ══════════════════════════════════════════════════════════════════════════════
#
#  At bit position b (1-indexed), knowing the first c bits correctly, the
#  probability of a correct guess with j timing samples is:
#
#       P = Φ( √( j·(b−c) / (2·(w−b)) ) )
#
#  where Φ is the standard normal CDF and w is the total exponent bit-length.
#
#  Inverting for j:
#
#       j = [ Φ⁻¹(P) ]² · 2·(w−b) / (b−c)
#
#  For the greedy attack (assuming all previous bits are correct): c = b−1,
#  so b−c = 1 always. The hardest bit is always the very first one (b=1),
#  where w−b is maximal.
# ─────────────────────────────────────────────────────────────────────────────

def success_probability(j: int, w: int, b: int, c: int) -> float:
    """
    Probability of a correct guess at bit b, given j timing samples.

    Parameters
    ----------
    j : number of timing measurements
    w : total exponent bit-length
    b : current bit position (1-indexed, as in the paper)
    c : number of correctly guessed bits strictly before b
        (for the greedy case: c = b−1; for the first bit: c = 0)

    Returns
    -------
    float in [0, 1]
    """
    if b >= w:
        return 1.0
    z = np.sqrt(j * (b - c) / (2 * (w - b)))
    return float(stats.norm.cdf(z))


def required_samples(w: int, target_prob: float, b: int = 1, c: int = 0) -> int:
    """
    Minimum number of timing samples to achieve *target_prob* at bit b.

    Parameters
    ----------
    w           : total exponent bit-length
    target_prob : desired probability of a correct guess (e.g. 0.95)
    b           : bit position (1-indexed); default 1 = hardest (first) bit
    c           : correctly guessed bits before b; default 0

    Returns
    -------
    int — number of samples required (rounded up)
    """
    if target_prob <= 0 or target_prob >= 1:
        raise ValueError("target_prob must be strictly between 0 and 1")
    z_p = stats.norm.ppf(target_prob)          # Φ⁻¹(P)
    j   = z_p ** 2 * 2 * (w - b) / (b - c)
    return int(np.ceil(j))


def print_sample_estimation(w: int, target_prob: float = 0.95) -> int:
    """
    Print a human-readable estimation report for the timing attack.

    Shows:
      • Required samples for the hardest bit (bit 1, the bottleneck)
      • How the per-bit success probability evolves as more bits are known
        (greedy scenario: c = b−1 at each step)

    Returns the number of samples required for the worst-case bit.

    Parameters
    ----------
    w           : total exponent bit-length
    target_prob : desired success probability per bit (default 0.95)
    """
    print(f"\n{'═' * 62}")
    print(f"  Sample Size Estimation  (w={w} bits, target P={target_prob:.0%})")
    print(f"{'═' * 62}")

    # Worst-case: bit 1 (first bit), c=0, requires the most samples
    j_needed = required_samples(w, target_prob, b=1, c=0)
    print(f"  Required samples (worst-case, bit 1) : {j_needed}")
    print()

    # Show how per-bit probability evolves with that fixed j
    # In the greedy scenario: at bit b, we assume c = b−1 previous bits correct
    print(f"  Per-bit success probability with j={j_needed} samples:")
    print(f"  {'Bit':>5}  {'c (known)':>10}  {'P(correct)':>12}")
    print(f"  {'-'*5}  {'-'*10}  {'-'*12}")

    for b in [1, 2, 5, 10, w // 4, w // 2, w - 2, w - 1]:
        if b >= w:
            continue
        c   = b - 1        # greedy: all previous bits assumed correct
        p   = success_probability(j_needed, w, b, c)
        print(f"  {b:>5}  {c:>10}  {p:>11.1%}")

    print(f"{'═' * 62}")
    return j_needed


# ══════════════════════════════════════════════════════════════════════════════
#  VERSION 1 — SIMPLE GREEDY
# ══════════════════════════════════════════════════════════════════════════════

def attack_v1(server: Server, m: int = 300, n_bits: int = 16) -> int:
    """
    Recover the first *n_bits* bits of the secret exponent, bit by bit.

    For each bit b (LSB first):
      1. Build two hypotheses: current_prefix | (0 << b)  and  | (1 << b)
      2. Compute corrected variance for each
      3. Commit to the bit with lower variance

    Returns the recovered integer (LSB-first bit ordering).
    """
    w = server._secret_key.bit_length()   # total exponent length (attacker can estimate this)

    print(f"\n{'═' * 62}")
    print(f"  Version 1 — Simple greedy  ({n_bits} bits, {m} samples)")
    print(f"  Exponent length w = {w} bits")
    print(f"{'═' * 62}")
    print(f"  {'Bit':>3}  {'Guess':>5}  {'P(theory)':>10}  {'Var(0)':>10}  {'Var(1)':>10}  {'Δ':>10}")
    print(f"  {'-'*3}  {'-'*5}  {'-'*10}  {'-'*10}  {'-'*10}  {'-'*10}")

    ys, Ts = collect_samples(server, m)
    recovered = 0                          # known prefix, grows one bit at a time

    for b in range(n_bits):
        vars_per_bit = {}

        for bit in (0, 1):
            hypothesis       = recovered | (bit << b)
            vars_per_bit[bit] = corrected_variance(Ts, ys, hypothesis, b + 1, server.n)

        best_bit  = min(vars_per_bit, key=vars_per_bit.get)
        recovered |= (best_bit << b)

        # Theoretical probability for this bit: b_paper = b+1, c_paper = b (greedy)
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
) -> int:
    """
    Recover the first *n_bits* bits using beam search.

    Instead of committing to a single bit at each step, we keep the
    *beam_width* best candidate prefixes ranked by corrected variance.

    This lets the attack recover from an earlier wrong guess:
    a wrong bit creates higher variance and will eventually be pruned,
    while the correct branch keeps climbing to the top.

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

        # Keep the beam_width candidates with the lowest variance
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
    # 64-bit RSA is toy-sized; real RSA uses ≥ 2048.
    # Tiny keys let the simulation run in seconds instead of hours.
    KEY_SIZE = 64   # total modulus bits
    N_BITS   = 16   # how many bits of d to recover
    TARGET_P = 0.90 # desired per-bit success probability

    print("  Setting up RSA server …")
    server = Server(key_size=KEY_SIZE)
    print(f"  Public key e = {bin(server.public_key)}")
    print(f"  Modulus    n = {server.n}")
    print(f"  Secret key d = [hidden from attacker]")

    # ── Step 1: estimate how many samples we need BEFORE attacking ───────────
    w        = server._secret_key.bit_length()   # attacker can estimate from key size
    M        = print_sample_estimation(w, target_prob=TARGET_P)

    # ── Step 2: run both attack versions with the estimated sample count ─────
    recovered_v1 = attack_v1(server, m=M, n_bits=N_BITS)
    recovered_v2 = attack_v2(server, m=M, n_bits=N_BITS, beam_width=8)

    # ── Summary ──────────────────────────────────────────────────────────────
    target = server._secret_key & ((1 << N_BITS) - 1)
    print(f"\n{'═' * 62}")
    print(f"  FINAL SUMMARY  ({N_BITS} LSBs of secret exponent d)")
    print(f"  Target   : {bin(target)}")
    print(f"  V1       : {bin(recovered_v1)}  {'✓' if recovered_v1 == target else '✗'}")
    print(f"  V2       : {bin(recovered_v2)}  {'✓' if recovered_v2 == target else '✗'}")
    print(f"{'═' * 62}")
