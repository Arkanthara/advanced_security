#!/usr/bin/env python3
"""
=============================================================================
RSA Timing Side-Channel Attack — Python Implementation
=============================================================================

OVERVIEW
--------
This is a faithful port of the C++ RSA timing attack to Python.
The key design constraint: we deliberately do NOT use Python's built-in
arbitrary-precision integers for the core arithmetic.  Instead, every
number is stored as a fixed-size array of 64-bit "limbs" (like the C++
BigInt<L>), and all operations work on those limbs explicitly.

This forces us to implement schoolbook multiplication, binary long division
for modular reduction, etc. — the same low-level routines as the C++ version.
It also means the timing of pow_mod depends on the bit pattern of the
exponent in exactly the same way, which is what the attack exploits.

STRUCTURE
---------
  1. BigInt          — fixed-width little-endian unsigned integer
  2. Arithmetic ops  — compare, subtract, multiply_wide, reduce,
                       mul_mod, pow_mod
  3. GMP ↔ BigInt    — conversion helpers using gmpy2
  4. RSA keygen      — using gmpy2 for primality testing
  5. Timing oracle   — measures decryption time
  6. Timing attack   — beam-search bit recovery (Kocher 1996)
  7. Main

DEPENDENCIES
------------
  pip install gmpy2

USAGE
-----
  python3 rsa_timing_attack.py [num_ciphertexts] [reps_per_cipher] [beam_width]
  python3 rsa_timing_attack.py 64 8 4

NOTE ON PERFORMANCE
-------------------
  Python is ~100× slower than C++ here, and the GIL adds timing noise.
  Use small MOD_LIMBS (4 = 256-bit) for experimentation.
  The attack logic is identical to the C++ version; the signal may be
  weaker due to Python's interpreter overhead.
=============================================================================
"""

from __future__ import annotations

import sys
import time
import random
import gmpy2
from typing import List, Tuple

# =============================================================================
# Section 1 — Configuration
# =============================================================================

# Number of 64-bit limbs in the RSA modulus n = p × q.
# MOD_LIMBS = 4  →  256-bit modulus, 128-bit primes.
MOD_LIMBS   = 4
PRIME_LIMBS = MOD_LIMBS // 2   # each prime is half the modulus width

assert MOD_LIMBS % 2 == 0, "MOD_LIMBS must be even"

# Mask used to keep values within a single 64-bit word.
MASK64 = (1 << 64) - 1

# =============================================================================
# Section 2 — BigInt: fixed-width, little-endian unsigned integer
# =============================================================================

class BigInt:
    """
    An unsigned integer stored as exactly `num_limbs` 64-bit words.

    Layout: little-endian — limbs[0] is least significant, limbs[-1] most.
    All limbs are Python ints in the range [0, 2^64 - 1].

    We never let Python's arbitrary-precision arithmetic do the heavy lifting:
    every operation is written word-by-word, explicitly masking to 64 bits.
    This mirrors the C++ BigInt<L> template.
    """

    __slots__ = ("num_limbs", "limbs")

    # -------------------------------------------------------------------------
    # Constructors
    # -------------------------------------------------------------------------

    def __init__(self, num_limbs: int, small_value: int = 0):
        """
        Create a BigInt with `num_limbs` limbs, initialised to `small_value`.
        Higher limbs are zero; `small_value` must fit in 64 bits.
        """
        self.num_limbs = num_limbs
        self.limbs: List[int] = [0] * num_limbs
        if small_value:
            self.limbs[0] = small_value & MASK64

    @classmethod
    def zero(cls, num_limbs: int) -> BigInt:
        return cls(num_limbs, 0)

    @classmethod
    def one(cls, num_limbs: int) -> BigInt:
        return cls(num_limbs, 1)

    def copy(self) -> BigInt:
        result = BigInt(self.num_limbs)
        result.limbs = self.limbs.copy()
        return result

    # -------------------------------------------------------------------------
    # Predicates
    # -------------------------------------------------------------------------

    def is_zero(self) -> bool:
        return all(word == 0 for word in self.limbs)

    def is_even(self) -> bool:
        return (self.limbs[0] & 1) == 0

    # -------------------------------------------------------------------------
    # Bit-level access
    # -------------------------------------------------------------------------

    def bit_length(self) -> int:
        """Index of the highest set bit + 1.  Returns 0 for zero."""
        for i in range(self.num_limbs - 1, -1, -1):
            if self.limbs[i] != 0:
                # Python int.bit_length() gives us what we need
                return i * 64 + self.limbs[i].bit_length()
        return 0

    def get_bit(self, bit_index: int) -> bool:
        """Read the bit at position `bit_index` (0 = LSB)."""
        word_index = bit_index // 64
        bit_offset = bit_index % 64
        if word_index >= self.num_limbs:
            return False
        return bool((self.limbs[word_index] >> bit_offset) & 1)

    def set_bit(self, bit_index: int, value: bool) -> None:
        """Set or clear the bit at position `bit_index`."""
        word_index = bit_index // 64
        bit_offset = bit_index % 64
        if word_index >= self.num_limbs:
            return
        if value:
            self.limbs[word_index] |= (1 << bit_offset)
        else:
            self.limbs[word_index] &= ~(1 << bit_offset)
        # Keep within 64 bits (the clear case can't overflow, but be safe)
        self.limbs[word_index] &= MASK64

    # -------------------------------------------------------------------------
    # Display
    # -------------------------------------------------------------------------

    def to_binary_string(self) -> str:
        """Return the binary representation, no leading zeros (minimum '0')."""
        length = self.bit_length()
        if length == 0:
            return "0"
        return "".join("1" if self.get_bit(i) else "0" for i in range(length - 1, -1, -1))

    def __repr__(self) -> str:
        return f"BigInt({self.num_limbs}, 0b{self.to_binary_string()})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BigInt):
            return NotImplemented
        return self.num_limbs == other.num_limbs and self.limbs == other.limbs


# =============================================================================
# Section 3 — Arithmetic on BigInt
# =============================================================================

def compare(a: BigInt, b: BigInt) -> int:
    """
    Three-way comparison.  Returns -1, 0, or +1.
    Scans from most-significant to least-significant limb.
    """
    for i in range(a.num_limbs - 1, -1, -1):
        if a.limbs[i] < b.limbs[i]: return -1
        if a.limbs[i] > b.limbs[i]: return +1
    return 0


def subtract(a: BigInt, b: BigInt) -> BigInt:
    """
    Return a - b.

    Caller must guarantee a >= b; no underflow check is performed.
    Uses the classic borrow-propagation algorithm, one limb at a time.
    Borrow is 0 or 1; when the limb difference goes negative we add 2^64
    (wrap around) and carry borrow=1 to the next limb.
    """
    result = BigInt(a.num_limbs)
    borrow = 0

    for i in range(a.num_limbs):
        difference = a.limbs[i] - b.limbs[i] - borrow
        if difference < 0:
            result.limbs[i] = difference + (1 << 64)  # wrap around
            borrow = 1
        else:
            result.limbs[i] = difference
            borrow = 0

    return result


def multiply_wide(a: BigInt, b: BigInt) -> BigInt:
    """
    Schoolbook O(L²) multiplication.

    Returns a × b as a BigInt with 2 × a.num_limbs limbs, so no information
    is lost.  We accumulate partial products word by word, carrying overflow
    to the next word.
    """
    L = a.num_limbs
    product = BigInt(2 * L)

    for i in range(L):
        carry = 0
        for j in range(L):
            # acc fits in 128 bits (64+64+64 at most), no risk of overflow in Python
            acc = product.limbs[i + j] + a.limbs[i] * b.limbs[j] + carry
            product.limbs[i + j] = acc & MASK64
            carry = acc >> 64
        # Propagate final carry into the upper half
        product.limbs[i + L] = (product.limbs[i + L] + carry) & MASK64

    return product


def reduce(x: BigInt, modulus: BigInt) -> BigInt:
    """
    Compute x mod modulus via binary long division.

    x has 2L limbs; modulus has L limbs.  We process x one bit at a time
    from MSB to LSB, maintaining a running remainder:
      - left-shift remainder by 1
      - bring in the next bit of x
      - if remainder >= modulus, subtract modulus

    This is O(bits²) but simple and easy to verify correct.
    """
    L = modulus.num_limbs
    remainder = BigInt(L)

    for bit_pos in range(x.bit_length() - 1, -1, -1):

        # Left-shift remainder by 1 bit (propagate carry from low to high)
        for k in range(L - 1, -1, -1):
            remainder.limbs[k] = (remainder.limbs[k] << 1) & MASK64
            # The MSB of the limb below becomes the LSB of this limb
            if k > 0 and (remainder.limbs[k - 1] >> 63):
                remainder.limbs[k] |= 1

        # Bring in the next bit from x
        if x.get_bit(bit_pos):
            remainder.limbs[0] |= 1

        # Keep remainder in [0, modulus)
        if compare(remainder, modulus) >= 0:
            remainder = subtract(remainder, modulus)

    return remainder


def mul_mod(a: BigInt, b: BigInt, modulus: BigInt) -> BigInt:
    """Return (a × b) mod modulus."""
    return reduce(multiply_wide(a, b), modulus)


def pow_mod(base: BigInt, exponent: BigInt, modulus: BigInt) -> BigInt:
    """
    Modular exponentiation via square-and-multiply (MSB first).

    For each bit of the exponent (high to low):
      - Always:   result ← result² mod modulus
      - If bit=1: result ← result × base mod modulus

    *** TIMING VULNERABILITY ***
    The extra multiply only happens on set bits.  This makes the execution
    time depend on the bit pattern of `exponent`, which is the secret we
    are trying to recover.  A constant-time implementation would always do
    both multiplies and discard one — but we intentionally skip that here.
    """
    result = BigInt.one(modulus.num_limbs)

    for bit_pos in range(exponent.bit_length() - 1, -1, -1):
        result = mul_mod(result, result, modulus)       # always square
        if exponent.get_bit(bit_pos):
            result = mul_mod(result, base, modulus)     # multiply only on 1-bits

    return result


# =============================================================================
# Section 4 — gmpy2 ↔ BigInt conversion helpers
# =============================================================================

def bigint_from_gmpy(z: gmpy2.mpz, num_limbs: int) -> BigInt:
    """
    Convert a gmpy2 integer to our BigInt representation.
    Extracts 64-bit limbs one by one from the Python int.
    """
    result = BigInt(num_limbs)
    value  = int(z)
    for i in range(num_limbs):
        result.limbs[i] = value & MASK64
        value >>= 64
    return result


def bigint_to_gmpy(x: BigInt) -> gmpy2.mpz:
    """
    Convert our BigInt to a gmpy2 integer.
    Reassembles 64-bit limbs into a single Python int (then wraps in mpz).
    """
    value = 0
    for i in range(x.num_limbs - 1, -1, -1):
        value = (value << 64) | x.limbs[i]
    return gmpy2.mpz(value)


# =============================================================================
# Section 5 — RSA Key Generation
# =============================================================================

class RSAKeyPair:
    """All RSA key material bundled together."""
    __slots__ = ("n", "e", "d", "phi", "p", "q")

    def __init__(self, n: BigInt, e: BigInt, d: BigInt, phi: BigInt,
                 p: BigInt, q: BigInt):
        self.n   = n    # public modulus       n = p × q
        self.e   = e    # public exponent      (65537)
        self.d   = d    # private exponent     d = e⁻¹ mod φ(n)
        self.phi = phi  # Euler totient        φ(n) = (p-1)(q-1)
        self.p   = p    # first prime factor
        self.q   = q    # second prime factor


def generate_prime(num_limbs: int) -> BigInt:
    """
    Generate a random prime with exactly num_limbs × 64 bits using gmpy2.

    We pick a random odd number with the MSB set (to guarantee the right
    bit-width), then call gmpy2.next_prime() to find the next prime.
    We repeat until the result still fits in exactly num_limbs × 64 bits.
    """
    bit_width = num_limbs * 64
    while True:
        candidate = gmpy2.mpz(random.getrandbits(bit_width))
        candidate |= gmpy2.mpz(1) << (bit_width - 1)   # set MSB  → full width
        candidate |= gmpy2.mpz(1)                        # set LSB  → odd

        prime = gmpy2.next_prime(candidate)

        if prime.bit_length() == bit_width:
            return bigint_from_gmpy(prime, num_limbs)


def modular_inverse(a: BigInt, m: BigInt) -> BigInt:
    """
    Compute a⁻¹ mod m using gmpy2.invert().
    Returns x such that a × x ≡ 1 (mod m).
    """
    gmp_a   = bigint_to_gmpy(a)
    gmp_m   = bigint_to_gmpy(m)
    inverse = gmpy2.invert(gmp_a, gmp_m)
    return bigint_from_gmpy(inverse, m.num_limbs)


def generate_rsa_keypair() -> RSAKeyPair:
    """
    Generate a fresh RSA key pair:

        p, q  ← random primes of PRIME_LIMBS × 64 bits
        n     = p × q
        φ(n)  = (p − 1)(q − 1)
        e     = 65537
        d     = e⁻¹ mod φ(n)
    """
    # Generate two distinct primes
    p = generate_prime(PRIME_LIMBS)
    q = generate_prime(PRIME_LIMBS)
    while compare(p, q) == 0:
        q = generate_prime(PRIME_LIMBS)

    # n = p × q — result fits in MOD_LIMBS limbs (each factor is PRIME_LIMBS wide)
    n_wide = multiply_wide(p, q)
    n = BigInt(MOD_LIMBS)
    n.limbs = n_wide.limbs[:MOD_LIMBS]

    # φ(n) = (p − 1)(q − 1)
    p_minus_one = subtract(p, BigInt(PRIME_LIMBS, 1))
    q_minus_one = subtract(q, BigInt(PRIME_LIMBS, 1))
    phi_wide = multiply_wide(p_minus_one, q_minus_one)
    phi = BigInt(MOD_LIMBS)
    phi.limbs = phi_wide.limbs[:MOD_LIMBS]

    e = BigInt(MOD_LIMBS, 65537)
    d = modular_inverse(e, phi)

    return RSAKeyPair(n=n, e=e, d=d, phi=phi, p=p, q=q)


# =============================================================================
# Section 6 — Timing Oracle
# =============================================================================

def measure_decryption_time(ciphertext: BigInt,
                            private_exponent: BigInt,
                            modulus: BigInt,
                            num_repetitions: int) -> float:
    """
    Return the average decryption time in nanoseconds over `num_repetitions`
    calls to pow_mod(ciphertext, private_exponent, modulus).

    Averaging reduces random noise, giving a more stable timing signal.
    """
    start = time.perf_counter_ns()
    for _ in range(num_repetitions):
        pow_mod(ciphertext, private_exponent, modulus)
    end = time.perf_counter_ns()

    return (end - start) / num_repetitions


# =============================================================================
# Section 7 — Timing Attack: recovering the private exponent bit by bit
# =============================================================================

def timing_score(candidate_exponent: BigInt,
                 ciphertexts: List[BigInt],
                 observed_times: List[float],
                 modulus: BigInt) -> float:
    """
    Compute how well `candidate_exponent` explains the observed timing data.

    For each ciphertext cᵢ and its observed decryption time tᵢ:
      - We time pow_mod(cᵢ, candidate_exponent, n) ourselves.
      - The residual rᵢ = tᵢ − (our time) captures timing variance that
        the candidate does NOT yet explain.

    We return the variance of these residuals.
    A correct guess for the bits recovered so far produces small residuals
    → low variance → better score.

    Lower score = better candidate.
    """
    residuals: List[float] = []

    for i, ciphertext in enumerate(ciphertexts):
        t0      = time.perf_counter_ns()
        pow_mod(ciphertext, candidate_exponent, modulus)
        t1      = time.perf_counter_ns()
        elapsed = t1 - t0

        residual = observed_times[i] - elapsed
        residuals.append(residual)

    n       = len(residuals)
    mean    = sum(residuals) / n
    variance = sum((r - mean) ** 2 for r in residuals) / n
    return variance   # lower is better


def recover_private_exponent(ciphertexts: List[BigInt],
                             observed_times: List[float],
                             key: RSAKeyPair,
                             beam_width: int) -> BigInt:
    """
    Recover the private exponent d bit by bit using a beam search.

    Algorithm (Kocher's timing attack, 1996):
      - We know the MSB of d is 1, so we start the beam there.
      - For each subsequent bit (from MSB-1 down to 0):
          * Extend every candidate in the beam by appending bit=0 and bit=1.
          * Score each extension with timing_score().
          * Keep only the `beam_width` best-scoring candidates.
      - The top candidate after all bits have been processed is our guess for d.

    `key` is only used for key.n (the public modulus) and key.d (for progress
    reporting / verification).  The attack itself only uses ciphertexts and
    observed_times.
    """
    num_bits = key.d.bit_length()

    # Start the beam: the MSB of d is always 1
    initial = BigInt.zero(MOD_LIMBS)
    initial.set_bit(num_bits - 1, True)
    beam: List[BigInt] = [initial]

    # Recover bits from (MSB - 1) down to 0
    for bit_index in range(num_bits - 2, -1, -1):

        # Generate all extensions: each current candidate extended with 0 or 1
        candidates: List[Tuple[BigInt, float]] = []

        for current in beam:
            for bit_value in (False, True):
                extension = current.copy()
                extension.set_bit(bit_index, bit_value)
                score = timing_score(extension, ciphertexts, observed_times, key.n)
                candidates.append((extension, score))

        # Keep the best `beam_width` candidates (lowest variance = better fit)
        candidates.sort(key=lambda pair: pair[1])
        beam = [candidate for candidate, _score in candidates[:beam_width]]

        # ---- Progress report ----
        best_candidate, best_score = candidates[0]
        guessed_bit = best_candidate.get_bit(bit_index)
        true_bit    = key.d.get_bit(bit_index)
        correct     = (guessed_bit == true_bit)

        status = "✓" if correct else "✗"
        print(f"  bit {bit_index:4d}: "
              f"guessed={int(guessed_bit)}  "
              f"true={int(true_bit)}  "
              f"score={best_score:.3e}  "
              f"{status}")

    return beam[0]   # best surviving candidate


# =============================================================================
# Section 8 — Main
# =============================================================================

def main() -> int:
    args = sys.argv[1:]
    num_ciphertexts     = int(args[0]) if len(args) > 0 else 32
    reps_per_ciphertext = int(args[1]) if len(args) > 1 else 4
    beam_width          = int(args[2]) if len(args) > 2 else 4

    print("=== RSA Timing Attack Demo (Python) ===")
    print(f"  Modulus size  : {MOD_LIMBS * 64} bits")
    print(f"  Ciphertexts   : {num_ciphertexts}")
    print(f"  Repetitions   : {reps_per_ciphertext} per ciphertext")
    print(f"  Beam width    : {beam_width}")
    print()

    # ------------------------------------------------------------------
    # Step 1: Generate the victim's RSA key pair
    # ------------------------------------------------------------------
    print("[1] Generating RSA key pair...")
    key = generate_rsa_keypair()
    print(f"    n = {key.n.to_binary_string()}")
    print(f"    d = {key.d.to_binary_string()}  (SECRET — shown for verification)")
    print()

    # ------------------------------------------------------------------
    # Step 2: Collect (ciphertext, decryption time) pairs
    # ------------------------------------------------------------------
    print("[2] Collecting timing samples...")
    ciphertexts: List[BigInt]  = []
    observed_times: List[float] = []

    rng = random.Random(42)

    for i in range(num_ciphertexts):
        # Build a random plaintext and encrypt: c = m^e mod n
        plaintext = BigInt(MOD_LIMBS)
        plaintext.limbs = [rng.getrandbits(64) & MASK64 for _ in range(MOD_LIMBS)]

        ciphertext = pow_mod(plaintext, key.e, key.n)
        ciphertexts.append(ciphertext)

        # Time the victim's decryption
        elapsed_ns = measure_decryption_time(ciphertext, key.d, key.n,
                                             reps_per_ciphertext)
        observed_times.append(elapsed_ns)

        print(f"    sample {i + 1}/{num_ciphertexts}  ({elapsed_ns:.0f} ns)    ",
              end="\r", flush=True)

    print()
    print()

    # ------------------------------------------------------------------
    # Step 3: Run the timing attack
    # ------------------------------------------------------------------
    print("[3] Running bit-by-bit timing attack...")
    recovered_d = recover_private_exponent(ciphertexts, observed_times,
                                           key, beam_width)

    # ------------------------------------------------------------------
    # Step 4: Report results
    # ------------------------------------------------------------------
    print()
    print("[4] Results")
    print(f"    Recovered d : {recovered_d.to_binary_string()}")
    print(f"    True d      : {key.d.to_binary_string()}")

    success = (compare(recovered_d, key.d) == 0)
    if success:
        print("\n  ✓ Full key recovered!")
    else:
        # Count how many bits differ
        wrong_bits = sum(
            recovered_d.get_bit(i) != key.d.get_bit(i)
            for i in range(key.d.bit_length())
        )
        print(f"\n  ✗ Key recovery failed ({wrong_bits} wrong bits).")
        print("    Try more ciphertexts or repetitions.")

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
