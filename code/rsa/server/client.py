"""
RSA Timing Attack — Client
==========================
Recovers the server's private exponent d by exploiting the timing side-channel
in fast_exp: when exponent bit b == 1, an extra modular multiplication is
performed, making that iteration measurably slower.

Two recovery strategies are implemented:

  Version 1 — Greedy: choose the hypothesis (bit=0 or bit=1) with the lower
  residual variance at each step and commit immediately.

  Version 2 — Beam search: maintain the BEAM_WIDTH best candidates at each
  step, expanding each with both hypotheses and pruning by variance. This
  tolerates early mistakes via backtracking.

Timing model
------------
For bit b of d, the server executes:
  - (always)      y = (y * y) % n      ← squaring
  - (iff d_b = 1) s = (s * y) % n      ← conditional multiply

Since y_b = y^(2^b) mod n depends only on the public input y, and s_b depends
only on bits 0..b-1 of d (already recovered), we can reproduce the first b+1
iterations locally and time them. When our partial exponent matches the true
prefix, the local times correlate with the server times; subtracting this
correlated component minimises the residual variance.

Usage
-----
    python client.py                  # run both versions
"""

import gc
import json
import random
import time
import urllib.request

import numpy as np

# ── Configuration ──────────────────────────────────────────────────────────────
SERVER_URL   = "http://localhost:8080"
N_SAMPLES    = 5000      # distinct ciphertexts per attack run
N_REPEATS    = 3        # server queries per ciphertext; median is taken
SLEEP_DELAY  = 0.0001    # seconds between queries (system stabilisation)
OUTLIER_Z    = 2.5      # z-score threshold for outlier rejection
BEAM_WIDTH   = 8        # Version 2: candidates kept per bit position


# ── Server I/O ─────────────────────────────────────────────────────────────────

def fetch_public_key() -> dict:
    """
    Fetch the server's public parameters.

    Returns
    -------
    dict
        Keys: "e" (public exponent), "n" (modulus), "key_bits" (bit-length of d).
    """
    with urllib.request.urlopen(SERVER_URL) as resp:
        return json.loads(resp.read())


def query_decryption_time(y: int) -> float:
    """
    Ask the server to decrypt y and return the measured wall-clock time.

    Parameters
    ----------
    y : int
        Ciphertext to submit.

    Returns
    -------
    float
        Server-reported decryption time in seconds.
    """
    body = json.dumps({"y": y}).encode()
    req  = urllib.request.Request(
        SERVER_URL, data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())["time"]


# ── Sample collection ──────────────────────────────────────────────────────────

def collect_samples(n: int) -> tuple[list[int], np.ndarray]:
    """
    Generate N_SAMPLES random ciphertexts and measure their decryption times.

    Each ciphertext is queried N_REPEATS times; the *median* is kept to suppress
    outliers caused by transient OS load. A brief sleep between consecutive
    queries lets the CPU stabilise.

    Parameters
    ----------
    n : int
        RSA modulus (upper bound for random ciphertexts).

    Returns
    -------
    y_vals : list[int]
        The N_SAMPLES ciphertext values.
    T : np.ndarray, shape (N_SAMPLES,)
        Median decryption time for each ciphertext.
    """
    y_vals = [random.randint(2, n - 1) for _ in range(N_SAMPLES)]
    T      = np.empty(N_SAMPLES)

    for i, y in enumerate(y_vals):
        reps = []
        for _ in range(N_REPEATS):
            reps.append(query_decryption_time(y))
            time.sleep(SLEEP_DELAY)
        T[i] = np.median(reps)

        if (i + 1) % 50 == 0:
            print(f"  Collected {i + 1}/{N_SAMPLES} samples …")

    return y_vals, T


def remove_outliers(y_vals: list[int], T: np.ndarray) -> tuple[list[int], np.ndarray]:
    """
    Drop samples whose timing deviates by more than OUTLIER_Z standard
    deviations from the mean.

    Parameters
    ----------
    y_vals : list[int]
        Ciphertext values.
    T : np.ndarray
        Corresponding timing measurements.

    Returns
    -------
    Filtered (y_vals, T) pair.
    """
    z    = np.abs((T - T.mean()) / T.std())
    mask = z < OUTLIER_Z
    return [y for y, keep in zip(y_vals, mask) if keep], T[mask]


# ── Local timing model ─────────────────────────────────────────────────────────

def simulate_partial(y_val: int, x_partial: int, n_bits: int, n: int) -> float:
    """
    Time the first *n_bits* iterations of fast_exp(y_val, x_partial, n).

    The loop mirrors the server's fast_exp exactly.  GC is disabled to reduce
    jitter.  Only the lowest n_bits bits of x_partial influence execution.

    Parameters
    ----------
    y_val : int
        Ciphertext base value.
    x_partial : int
        Exponent hypothesis (bits 0 … n_bits-1 matter).
    n_bits : int
        Number of fast_exp loop iterations to run (= current bit index + 1).
    n : int
        RSA modulus.

    Returns
    -------
    float
        Elapsed time in seconds for the simulated prefix.
    """
    s     = 1
    y_cur = y_val % n

    gc.disable()
    t0 = time.perf_counter()
    for b in range(n_bits):
        if (x_partial >> b) & 1:
            s = (s * y_cur) % n     # conditional multiply (timing leakage source)
        y_cur = (y_cur * y_cur) % n # squaring (always executed)
    t1 = time.perf_counter()
    gc.enable()

    return t1 - t0


def local_times(y_vals: list[int], x_partial: int, n_bits: int, n: int) -> np.ndarray:
    """
    Compute simulate_partial for every ciphertext under a single hypothesis.

    Parameters
    ----------
    y_vals : list[int]
        Ciphertext samples.
    x_partial : int
        Exponent hypothesis.
    n_bits : int
        Iterations to simulate (= bit index + 1).
    n : int
        RSA modulus.

    Returns
    -------
    np.ndarray, shape (len(y_vals),)
        Local simulation time per sample.
    """
    return np.array([simulate_partial(y, x_partial, n_bits, n) for y in y_vals])


# ── Variance analysis ──────────────────────────────────────────────────────────

def residual_variance(T: np.ndarray, t_hat: np.ndarray) -> float:
    """
    Compute Var(T − α·t_hat), where α is the OLS-optimal scale.

    The optimal scale α = Cov(T, t_hat) / Var(t_hat) removes the component of
    T that is linearly explained by t_hat.  A lower residual variance indicates
    that t_hat is a better model of the server's timing, i.e. the hypothesis is
    more likely correct.

    Parameters
    ----------
    T : np.ndarray
        Server timing measurements.
    t_hat : np.ndarray
        Local simulation times under a given hypothesis.

    Returns
    -------
    float
        Variance of the OLS residuals.
    """
    var_t = np.var(t_hat)
    if var_t < 1e-30:           # degenerate: all samples identical → no signal
        return float(np.var(T))
    alpha     = np.cov(T, t_hat)[0, 1] / var_t
    residuals = T - alpha * t_hat
    return float(np.var(residuals))


# ── Version 1: Greedy bit-by-bit recovery ─────────────────────────────────────

def recover_v1(y_vals: list[int], T: np.ndarray, key_bits: int, n: int) -> int:
    """
    Recover the private exponent greedily, one bit at a time.

    For each bit position b, two hypotheses are tested (d_b = 0 or d_b = 1).
    The hypothesis that yields the lower residual variance — i.e. whose local
    timing model better fits the server timings — is committed immediately.

    Parameters
    ----------
    y_vals : list[int]
        Ciphertext samples.
    T : np.ndarray
        Server timing measurements.
    key_bits : int
        Number of bits in the private exponent.
    n : int
        RSA modulus.

    Returns
    -------
    int
        Recovered exponent (LSB-first accumulation of chosen bits).
    """
    x = 0  # accumulates recovered bits

    for b in range(key_bits):
        best_bit, best_var = 0, float("inf")

        for h in (0, 1):            # hypothesis: bit b equals h
            x_h   = x | (h << b)
            t_h   = local_times(y_vals, x_h, b + 1, n)
            var_h = residual_variance(T, t_h)

            if var_h < best_var:
                best_var, best_bit = var_h, h

        x |= best_bit << b
        print(f"  bit {b:3d} → {best_bit}   (var ratio = {best_var:.3e})")

    return x


# ── Version 2: Beam-search with error correction ───────────────────────────────

def recover_v2(y_vals: list[int], T: np.ndarray, key_bits: int, n: int) -> int:
    """
    Recover the private exponent via beam search.

    At each bit position b, every surviving candidate is expanded by appending
    both bit=0 and bit=1, yielding 2·BEAM_WIDTH new candidates.  These are
    scored by residual variance and the top BEAM_WIDTH are kept.  This allows
    the search to correct early mis-decisions that a greedy approach cannot fix.

    Parameters
    ----------
    y_vals : list[int]
        Ciphertext samples.
    T : np.ndarray
        Server timing measurements.
    key_bits : int
        Number of bits in the private exponent.
    n : int
        RSA modulus.

    Returns
    -------
    int
        Best candidate exponent at the end of the search (lowest total variance).
    """
    candidates: list[int] = [0]  # start with the empty prefix

    for b in range(key_bits):
        # Expand and score all (candidate, hypothesis) pairs
        scored: list[tuple[float, int]] = []
        for x_b in candidates:
            for h in (0, 1):
                x_h   = x_b | (h << b)
                t_h   = local_times(y_vals, x_h, b + 1, n)
                var_h = residual_variance(T, t_h)
                scored.append((var_h, x_h))

        # Prune: keep only the BEAM_WIDTH candidates with lowest variance
        scored.sort(key=lambda item: item[0])
        candidates = [x for _, x in scored[:BEAM_WIDTH]]

        best_var, best_x = scored[0]
        print(f"  bit {b:3d} → beam top = {best_x:#x}  (var = {best_var:.3e})")

    return candidates[0]  # candidate with globally lowest variance


# ── Key verification ───────────────────────────────────────────────────────────

def verify(d_candidate: int, e: int, n: int) -> bool:
    """
    Verify a recovered private key by round-trip encrypt/decrypt.

    Encrypts a random message with the public key (e, n), decrypts with
    d_candidate, and checks equality.

    Parameters
    ----------
    d_candidate : int
        Recovered private exponent.
    e : int
        Public exponent.
    n : int
        RSA modulus.

    Returns
    -------
    bool
        True if decryption recovers the original message.
    """
    def fast_exp(y, x, mod):
        s, y = 1, y % mod
        while x:
            if x & 1:
                s = (s * y) % mod
            y = (y * y) % mod
            x >>= 1
        return s

    m      = random.randint(2, n - 1)
    cipher = fast_exp(m, e, n)
    return fast_exp(cipher, d_candidate, n) == m


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    print("=== RSA Timing Attack Client ===\n")

    # ── 1. Fetch public parameters ─────────────────────────────────────────────
    pub      = fetch_public_key()
    e, n, key_bits = pub["e"], pub["n"], pub["key_bits"]
    print(f"e        = {e}\nn        = {n}\nkey_bits = {key_bits}\n")

    # ── 2. Collect and clean timing samples ────────────────────────────────────
    print(f"Collecting {N_SAMPLES} samples ({N_REPEATS} repeats each) …")
    y_vals, T = collect_samples(n)
    y_vals, T = remove_outliers(y_vals, T)
    print(f"After outlier removal: {len(T)} samples retained.\n")

    # ── 3. Version 1 ───────────────────────────────────────────────────────────
    print("── Version 1: greedy ──")
    d_v1 = recover_v1(y_vals, T, key_bits, n)
    ok1  = verify(d_v1, e, n)
    print(f"\nRecovered d = {d_v1}")
    print(f"Verify      : {'PASS ✓' if ok1 else 'FAIL ✗'}\n")

    # ── 4. Version 2 ───────────────────────────────────────────────────────────
    print(f"── Version 2: beam search (width={BEAM_WIDTH}) ──")
    d_v2 = recover_v2(y_vals, T, key_bits, n)
    ok2  = verify(d_v2, e, n)
    print(f"\nRecovered d = {d_v2}")
    print(f"Verify      : {'PASS ✓' if ok2 else 'FAIL ✗'}\n")


if __name__ == "__main__":
    main()
