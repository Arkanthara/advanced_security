"""
kocher_attack.py
================
Kocher's 1996 timing attack on RSA, parallelised with joblib.

CORE IDEA
---------
RSA decryption computes  message = cipher^d mod n  using square-and-multiply.
The algorithm processes the secret exponent d bit by bit:

    result = 1
    while d > 0:
        if d & 1:                          # bit = 1  →  one EXTRA multiplication
            result = result * base mod n
        base = base * base mod n           # always squared
        d  >>= 1

When a bit of d is 1, the server does one extra modular multiplication.
That extra work leaks through the wall-clock time of the operation.

STATISTICAL STRATEGY  (Kocher §4)
----------------------------------
Let  T_i  = total server decryption time for ciphertext i.

We recover d one bit at a time (LSB first).  At bit position b, we already
know bits 0..b-1 (our "prefix").  We try both hypotheses for bit b (0 or 1):

    residual_i = T_i  −  local_estimate(ciphertext_i, hypothesis)

If the hypothesis is CORRECT, local_estimate explains exactly the variance
introduced by bits 0..b, so Var(residual) is minimised.
If WRONG, the subtracted estimate is mis-correlated → Var(residual) is higher.

We keep the hypothesis with the lower residual variance.

BEAM SEARCH  (self-correcting)
-------------------------------
Instead of committing to a single bit at each step (greedy), we keep the
top-k candidates ranked by residual variance.  A wrong bit raises the
variance of that branch and will be pruned; the correct branch rises to
the top.  This makes the attack resilient to individual mis-classifications.

REQUIREMENTS
------------
    pip install numpy joblib scipy
    (your own rsa.py must expose an RSA class with a createKeyPair method)

USAGE
-----
    python kocher_attack.py
"""

import time
import random

import numpy as np
from joblib import Parallel, delayed

from rsa import RSA   # ← your own implementation


# ─────────────────────────────────────────────────────────────────────────────
#  RSA SERVER  (simulates the target machine whose timing we measure)
# ─────────────────────────────────────────────────────────────────────────────

def modular_multiply_with_cost(a: int, b: int, modulus: int) -> int:
    """
    Modular multiplication in pure Python, to keep timing differences visible.

    WHY PURE PYTHON and not built-in pow()?
    pow(base, exp, mod) is implemented in C and runs in near-constant time
    from Python's perspective — the bit-level timing differences are invisible.
    This hand-written loop keeps every multiplication at the Python level,
    where 512-bit bigint operations take ~10-50 µs each and are measurable.
    """
    x = a * b
    k = x // modulus
    x = x - k * modulus
    return x

def square_and_multiply(base: int, exponent: int, modulus: int) -> int:
    """
    Modular exponentiation in pure Python, LSB first.

    WHY PURE PYTHON and not built-in pow()?
    pow(base, exp, mod) is implemented in C and runs in near-constant time
    from Python's perspective — the bit-level timing differences are invisible.
    This hand-written loop keeps every multiplication at the Python level,
    where 512-bit bigint operations take ~10-50 µs each and are measurable.
    """
    result = 1
    base   = base % modulus

    while exponent > 0:
        if exponent & 1:
            result   = modular_multiply_with_cost(result, base, modulus)  # extra multiply when bit = 1
        base      = modular_multiply_with_cost(base, base, modulus)       # squaring — always executed
        exponent >>= 1

    return result


class RSAServer:
    """
    Simulates an RSA server that holds a secret key and leaks decryption timing.

    The attacker is allowed to:
      - read the public key (n, e)
      - submit any ciphertext and receive the elapsed decryption time

    The attacker must NOT directly read the secret key d.
    (d is exposed only to verify the recovered bits at the end.)
    """

    def __init__(self, key_size_bits: int = 512):
        """
        Generate a fresh RSA key pair.

        key_size_bits = 512 is the practical minimum for Python-level timing
        to be measurable.  64-bit keys are too fast; OS scheduling jitter
        (~100 µs) completely swamps the per-bit signal (~10 ns at 64 bits).
        """
        rsa = RSA()
        self.modulus, self.public_exponent, self.secret_exponent = (
            rsa.createKeyPair(key_size_bits)
        )

    def decrypt_and_measure(self, ciphertext: int, num_repeats: int = 15) -> float:
        """
        Decrypt *ciphertext* and return the median elapsed time in nanoseconds.

        We repeat the decryption num_repeats times and take the MEDIAN —
        not the mean.  A single OS scheduling spike can inflate one run by
        milliseconds; the median is unaffected as long as fewer than half
        the runs are disturbed.
        """
        elapsed_times = []
        for _ in range(num_repeats):
            t_start = time.perf_counter_ns()
            square_and_multiply(ciphertext, self.secret_exponent, self.modulus)
            elapsed_times.append(time.perf_counter_ns() - t_start)

        return float(np.median(elapsed_times))


# ─────────────────────────────────────────────────────────────────────────────
#  SAMPLE COLLECTION  (attacker sends crafted ciphertexts, records timing)
# ─────────────────────────────────────────────────────────────────────────────

def _collect_one_timing_sample(
    modulus:          int,
    public_exponent:  int,
    secret_exponent:  int,   # passed in so the worker is self-contained
    num_repeats:      int,
) -> tuple[int, float]:
    """
    Generate one random plaintext, encrypt it, measure the server decryption.

    This is a free (module-level) function — not a method — because joblib
    serialises tasks with pickle, which cannot handle bound methods or lambdas.

    Returns
    -------
    (ciphertext, median_decryption_time_ns)
    """
    plaintext  = random.randint(2, modulus - 1)
    ciphertext = pow(plaintext, public_exponent, modulus)   # attacker encrypts — C pow() is fine here

    elapsed_times = []
    for _ in range(num_repeats):
        t_start = time.perf_counter_ns()
        square_and_multiply(ciphertext, secret_exponent, modulus)
        elapsed_times.append(time.perf_counter_ns() - t_start)

    return ciphertext, float(np.median(elapsed_times))


def collect_timing_measurements(
    server:    RSAServer,
    num_samples:  int,
    num_repeats:  int  = 15,
    num_jobs:     int  = -1,
) -> tuple[list[int], np.ndarray]:
    """
    Collect *num_samples* (ciphertext, decryption_time) pairs in parallel.

    Each sample is independent — the server has no session state — so we can
    distribute them freely across workers with no synchronisation needed.

    Parameters
    ----------
    server       : the target server
    num_samples  : how many ciphertexts to send  (more → lower variance)
    num_repeats  : repetitions per ciphertext for median timing
    num_jobs     : joblib worker count  (-1 = all cores)

    Returns
    -------
    ciphertexts        : list of int
    decryption_times   : np.ndarray of float (nanoseconds)
    """
    raw_results = Parallel(n_jobs=num_jobs, prefer="processes")(
        delayed(_collect_one_timing_sample)(
            server.modulus, server.public_exponent, server.secret_exponent, num_repeats
        )
        for _ in range(num_samples)
    )

    ciphertexts      = [pair[0] for pair in raw_results]
    decryption_times = np.array([pair[1] for pair in raw_results], dtype=float)
    return ciphertexts, decryption_times


# ─────────────────────────────────────────────────────────────────────────────
#  HYPOTHESIS SCORING  (the statistical core of the attack)
# ─────────────────────────────────────────────────────────────────────────────

def estimate_partial_decryption_time(
    ciphertext:       int,
    exponent_prefix:  int,
    num_prefix_bits:  int,
    modulus:          int,
    num_repeats:      int = 15,
) -> float:
    """
    Locally simulate the first *num_prefix_bits* iterations of square_and_multiply
    and return the median elapsed time in nanoseconds.

    This gives our local estimate of how much of the server's decryption time
    is "explained" by the known prefix of the exponent.  Crucially we use the
    SAME algorithm and SAME Python bigint arithmetic as the server, so the
    correlation between local and server timings holds.
    """
    elapsed_times = []
    for _ in range(num_repeats):
        result   = 1
        base     = ciphertext % modulus
        exponent = exponent_prefix

        t_start = time.perf_counter_ns()
        for _ in range(num_prefix_bits):
            if exponent & 1:
                result   = modular_multiply_with_cost(result, base, modulus)
            base      = modular_multiply_with_cost(base, base, modulus)
            exponent >>= 1
        elapsed_times.append(time.perf_counter_ns() - t_start)

    return float(np.median(elapsed_times))


def _score_one_hypothesis(
    exponent_candidate: int,
    num_prefix_bits:    int,
    modulus:            int,
    ciphertexts:        list[int],
    decryption_times:   np.ndarray,
) -> tuple[float, int]:
    """
    Score one exponent candidate by computing Var(T_i − local_estimate_i).

    Lower variance means the candidate better explains the server's timing.

    This is a free function (not a method) so joblib can pickle it by name.

    Returns
    -------
    (residual_variance, exponent_candidate)
    """
    local_estimates = np.array([
        estimate_partial_decryption_time(
            ciphertext, exponent_candidate, num_prefix_bits, modulus
        )
        for ciphertext in ciphertexts
    ])

    residuals = decryption_times - local_estimates
    return float(np.var(residuals)), exponent_candidate


# ─────────────────────────────────────────────────────────────────────────────
#  BEAM SEARCH ATTACK
# ─────────────────────────────────────────────────────────────────────────────

def recover_exponent_bits_beam(
    server:       RSAServer,
    num_samples:  int = 300,
    bits_to_recover: int = 16,
    beam_width:   int = 8,
    num_jobs:     int = -1,
) -> int:
    """
    Recover the first *bits_to_recover* LSBs of the secret exponent d.

    Algorithm
    ---------
    We maintain a beam of the top *beam_width* exponent prefix candidates,
    ranked by their residual variance score (lower = more likely correct).

    At each bit position b  (0 = LSB):
      1. Expand every candidate by appending both a 0-bit and a 1-bit.
      2. Score all expanded candidates in parallel (residual variance).
      3. Prune back to the top *beam_width* (lowest variance).

    A wrong bit inflates residual variance and eventually falls off the beam;
    the correct branch accumulates low variance and stays at the top.

    Parameters
    ----------
    server           : the RSA server to attack
    num_samples      : number of timing measurements to collect
    bits_to_recover  : how many LSBs of d to recover
    beam_width       : beam size  (larger → more resilient, slower)
    num_jobs         : joblib parallelism  (-1 = all cores)

    Returns
    -------
    Recovered integer (bit 0 = LSB of d, bit bits_to_recover-1 = MSB of range)
    """
    print(f"\n{'─' * 60}")
    print(f"  Beam attack  |  {bits_to_recover} bits  |  beam={beam_width}  |  {num_samples} samples")
    print(f"{'─' * 60}")

    # ── Step 1: collect timing measurements ──────────────────────────────────
    print(f"\n  Collecting {num_samples} timing samples …")
    ciphertexts, decryption_times = collect_timing_measurements(
        server, num_samples, num_jobs=num_jobs
    )
    print(
        f"  Done.  mean={np.mean(decryption_times):.0f} ns  "
        f"std={np.std(decryption_times):.0f} ns\n"
    )

    # ── Step 2: bit-by-bit beam search ───────────────────────────────────────
    # Each candidate is (residual_variance, exponent_prefix_so_far).
    # We start with a single empty prefix (no bits known yet).
    beam: list[tuple[float, int]] = [(0.0, 0)]

    for bit_position in range(bits_to_recover):

        # Expand: try appending bit=0 and bit=1 to every current candidate
        expanded_candidates = [
            exponent_prefix | (bit_value << bit_position)
            for _, exponent_prefix in beam
            for bit_value in (0, 1)
        ]

        # Score all expanded candidates in parallel — this is the bottleneck
        scored_candidates: list[tuple[float, int]] = Parallel(
            n_jobs=num_jobs, prefer="processes"
        )(
            delayed(_score_one_hypothesis)(
                candidate, bit_position + 1, server.modulus, ciphertexts, decryption_times
            )
            for candidate in expanded_candidates
        )

        # Prune: keep only the beam_width candidates with the lowest variance
        scored_candidates.sort(key=lambda pair: pair[0])
        beam = scored_candidates[:beam_width]

        # Progress report: show top-3 candidates for this bit
        actual_bit  = (server.secret_exponent >> bit_position) & 1
        guessed_bit = (beam[0][1] >> bit_position) & 1
        correct     = "✓" if guessed_bit == actual_bit else "✗"

        top3_summary = "  |  ".join(
            f"{bin(candidate)}  var={variance:.2e}"
            for variance, candidate in beam[:3]
        )
        print(f"  bit {bit_position:2d} {correct}  →  {top3_summary}")

    # ── Step 3: report result ─────────────────────────────────────────────────
    best_candidate = beam[0][1]
    target_bits    = server.secret_exponent & ((1 << bits_to_recover) - 1)
    success        = best_candidate == target_bits

    print(f"\n  Recovered : {bin(best_candidate)}")
    print(f"  Expected  : {bin(target_bits)}")
    print(f"  Result    : {'✓ CORRECT' if success else '✗ WRONG'}")
    print(f"{'─' * 60}\n")

    return best_candidate


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # The  if __name__ == "__main__"  guard is REQUIRED when using joblib on
    # Windows and macOS.  Those platforms spawn new processes by re-importing
    # the module from scratch; without the guard each worker would spawn more
    # workers, creating an infinite fork loop.

    random.seed(42)

    print("  Setting up RSA server …")
    server = RSAServer(key_size_bits=1024)
    print(f"  n = {server.modulus.bit_length()} bits,  e = {server.public_exponent}")
    print(f"  d = [hidden from attacker]")

    recover_exponent_bits_beam(
        server,
        num_samples     = 2000,
        bits_to_recover = 16,
        beam_width      = 10,
        num_jobs        = -1,   # use all CPU cores
    )
