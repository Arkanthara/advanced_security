#!/usr/bin/env python3
"""
RSA Timing Side-Channel Attack — compact NumPy implementation.

A BigInt is a np.ndarray of shape (L,) and dtype np.uint64, little-endian:
  limbs[0] = least-significant 64-bit word.

All arithmetic is schoolbook, word-by-word — no Python big-int shortcuts
for multiplication or reduction.  gmpy2 is only used for primality testing
and modular inverse.
"""

import sys, time, random
import numpy as np
import gmpy2

# ── Configuration ──────────────────────────────────────────────────────────────

MOD_LIMBS   = 2               # 64-bit limbs in n = p × q  →  256-bit RSA
PRIME_LIMBS = MOD_LIMBS // 2  # each prime is half the modulus width

# ── BigInt helpers ─────────────────────────────────────────────────────────────

def bigint(L: int, v: int = 0) -> np.ndarray:
    """Allocate a zero BigInt of L uint64 limbs, optionally set to small value v."""
    a = np.zeros(L, dtype=np.uint64)
    if v: a[0] = np.uint64(v)
    return a

def bit_len(a: np.ndarray) -> int:
    """Position of the highest set bit + 1  (0 for zero)."""
    for i in range(len(a) - 1, -1, -1):
        if a[i]: return i * 64 + int(a[i]).bit_length()
    return 0

def get_bit(a: np.ndarray, i: int) -> bool:
    w, b = i // 64, np.uint64(i % 64)
    return bool((a[w] >> b) & np.uint64(1)) if w < len(a) else False

def set_bit(a: np.ndarray, i: int, v: bool) -> None:
    w, b = i // 64, np.uint64(i % 64)
    if w < len(a):
        mask = np.uint64(1) << b
        if v: a[w] |= mask
        else: a[w] &= ~mask          # ~np.uint64 gives correct bitwise NOT

def to_bits(a: np.ndarray) -> str:
    n = bit_len(a)
    return ''.join('1' if get_bit(a, i) else '0' for i in range(n-1, -1, -1)) if n else '0'

# ── Arithmetic ─────────────────────────────────────────────────────────────────

def compare(a: np.ndarray, b: np.ndarray) -> int:
    for i in range(len(a) - 1, -1, -1):
        if a[i] < b[i]: return -1
        if a[i] > b[i]: return  1
    return 0

def subtract(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """a − b with borrow propagation. Caller must ensure a ≥ b."""
    r, borrow = np.zeros(len(a), dtype=np.uint64), 0
    for i in range(len(a)):
        d = int(a[i]) - int(b[i]) - borrow
        r[i], borrow = np.uint64(d % (1 << 64)), int(d < 0)
    return r

def multiply_wide(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """
    Schoolbook O(L²) multiplication → 2L-limb result.
    Intermediate sums go through Python int to hold up to 192 bits safely,
    then get split back into (low 64 bits, carry).
    """
    L, p = len(a), np.zeros(2 * len(a), dtype=np.uint64)
    for i in range(L):
        carry = 0
        for j in range(L):
            acc       = int(p[i+j]) + int(a[i]) * int(b[j]) + carry
            p[i+j]    = np.uint64(acc & 0xFFFF_FFFF_FFFF_FFFF)
            carry     = acc >> 64
        p[i+L] = np.uint64(int(p[i+L]) + carry)
    return p

def reduce(x: np.ndarray, m: np.ndarray) -> np.ndarray:
    """
    Binary long division: x mod m.
    x has 2L limbs; m has L limbs.  Processes one bit of x at a time from MSB:
    left-shift the running remainder, bring in the next bit, subtract m if needed.

    Left-shift of all L limbs at once with NumPy:
      the MSB of limb k becomes the LSB of limb k+1 via a carry array.
    """
    r = np.zeros(len(m), dtype=np.uint64)
    for pos in range(bit_len(x) - 1, -1, -1):
        carries = np.concatenate([[np.uint64(0)], r[:-1] >> np.uint64(63)])
        r = (r << np.uint64(1)) | carries        # shift whole number left by 1 bit
        if get_bit(x, pos): r[0] |= np.uint64(1)
        if compare(r, m) >= 0: r = subtract(r, m)
    return r

def mul_mod(a, b, m): return reduce(multiply_wide(a, b), m)

def pow_mod(base, exp, m):
    """
    Square-and-multiply (MSB-first).
    The multiply only runs on set bits → timing depends on the bit pattern of exp.
    This is the intentional vulnerability we exploit.
    """
    r = bigint(len(m), 1)
    for i in range(bit_len(exp) - 1, -1, -1):
        r = mul_mod(r, r, m)
        if get_bit(exp, i): r = mul_mod(r, base, m)    # ← timing leak
    return r

# ── gmpy2 bridge ───────────────────────────────────────────────────────────────

def to_int(a: np.ndarray) -> int:
    return sum(int(a[i]) << (64 * i) for i in range(len(a)))

def from_int(v: int, L: int) -> np.ndarray:
    a = np.zeros(L, dtype=np.uint64)
    for i in range(L): a[i], v = np.uint64(v & 0xFFFF_FFFF_FFFF_FFFF), v >> 64
    return a

# ── RSA key generation ─────────────────────────────────────────────────────────

def gen_prime(L: int) -> np.ndarray:
    """Random prime of exactly L×64 bits, found via gmpy2.next_prime."""
    bits = L * 64
    while True:
        candidate = gmpy2.mpz(random.getrandbits(bits)) | (1 << (bits - 1)) | 1
        prime = gmpy2.next_prime(candidate)
        if prime.bit_length() == bits:
            return from_int(int(prime), L)

def gen_rsa():
    """Generate (n, e, d): 256-bit RSA key pair."""
    p, q = gen_prime(PRIME_LIMBS), gen_prime(PRIME_LIMBS)
    while compare(p, q) == 0: q = gen_prime(PRIME_LIMBS)

    one = bigint(PRIME_LIMBS, 1)
    n   = multiply_wide(p, q)[:MOD_LIMBS].copy()
    phi = multiply_wide(subtract(p, one), subtract(q, one))[:MOD_LIMBS].copy()
    e   = bigint(MOD_LIMBS, 65537)
    d   = from_int(int(gmpy2.invert(to_int(e), to_int(phi))), MOD_LIMBS)
    return n, e, d

# ── Timing oracle ──────────────────────────────────────────────────────────────

def timed_decrypt(c, d, n, reps=1):
    t = time.perf_counter_ns()
    for _ in range(reps): pow_mod(c, d, n)
    return (time.perf_counter_ns() - t) / reps

# ── Timing attack ──────────────────────────────────────────────────────────────

def timing_score(g, ciphers, observed, n):
    """
    Variance of (observed_time − our_time_with_g) over all ciphertexts.

    A correct partial guess explains part of the timing variation, making
    the residuals smaller → lower variance → better score.
    """
    our_times = np.array([timed_decrypt(c, g, n) for c in ciphers])
    return float(np.var(np.asarray(observed) - our_times))

def recover_d(ciphers, observed, n, d_true, beam_width):
    """
    Recover d bit by bit with a beam search (Kocher's timing attack, 1996).
    At each step, extend every beam candidate with bit=0 and bit=1,
    keep the beam_width best-scoring ones.  d_true is only for reporting.
    """
    nbits = bit_len(d_true)
    seed  = bigint(MOD_LIMBS); set_bit(seed, nbits - 1, True)
    beam  = [seed]

    for b in range(nbits - 2, -1, -1):
        scored = []
        for cur in beam:
            for v in (False, True):
                ext = cur.copy(); set_bit(ext, b, v)
                scored.append((ext, timing_score(ext, ciphers, observed, n)))

        scored.sort(key=lambda x: x[1])
        beam = [c for c, _ in scored[:beam_width]]

        guess, truth = get_bit(beam[0], b), get_bit(d_true, b)
        print(f"  bit {b:4d}: guess={int(guess)} true={int(truth)}"
              f"  score={scored[0][1]:.3e}  {'✓' if guess == truth else '✗'}")

    return beam[0]

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]
    N, reps, beam_width = (int(args[i]) if i < len(args) else d
                           for i, d in enumerate([32, 4, 4]))

    print(f"=== RSA Timing Attack | {MOD_LIMBS*64}-bit | {N} samples | beam={beam_width} ===\n")

    print("[1] Generating RSA key pair...")
    n, e, d = gen_rsa()
    print(f"    n = {to_bits(n)}\n    d = {to_bits(d)}  (secret)\n")

    print("[2] Collecting timing samples...")
    rng = random.Random(42)
    ciphers, observed = [], []
    for i in range(N):
        m = from_int(rng.getrandbits(MOD_LIMBS * 64), MOD_LIMBS)
        ciphers.append(pow_mod(m, e, n))
        t = timed_decrypt(ciphers[-1], d, n, reps)
        observed.append(t)
        print(f"    {i+1}/{N}  ({t:.0f} ns)", end='\r', flush=True)
    print("\n")

    print("[3] Recovering d bit by bit...")
    recovered = recover_d(ciphers, observed, n, d, beam_width)

    print(f"\n[4] recovered = {to_bits(recovered)}")
    print(f"    true d    = {to_bits(d)}")
    ok = compare(recovered, d) == 0
    print("\n  ✓ Full key recovered!" if ok else
          "\n  ✗ Failed — try more samples or repetitions.")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
