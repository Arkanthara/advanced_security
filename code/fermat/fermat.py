"""
Fermat's Factorization Attack on RSA
=====================================
Demonstrates how Fermat's method can factor an RSA modulus n = p * q
when p and q are close to each other (weak key generation).

The method exploits the algebraic identity:
    n = x² - y²  =  (x + y)(x - y)
where x = (p + q) / 2  and  y = (p - q) / 2.
"""

import math
from rsa import RSA

# ---------------------------------------------------------------------------
# Fermat's Factorization
# ---------------------------------------------------------------------------

def is_perfect_square(n):
    """
    Check whether n is a perfect square and return its integer square root.

    Parameters
    ----------
    n : int
        Non-negative integer to test.

    Returns
    -------
    int or None
        Integer square root if n is a perfect square, else None.
    """
    root = math.isqrt(n)
    return root if root * root == n else None


def fermat_factor(n):
    """
    Factor n = p * q using Fermat's difference-of-squares method.

    Works by finding integers x, y such that n = x² − y²,
    then returning (x − y, x + y) as the two factors.

    Best suited for n whose prime factors are close to √n.

    Parameters
    ----------
    n : int
        Odd composite integer to factor (RSA modulus).

    Returns
    -------
    tuple[int, int]
        The two non-trivial factors (p, q) of n.

    Notes
    -----
    Time complexity grows with the gap |p − q|; for distant primes
    this degenerates to trial division speed.
    """
    # Step 1 — start just above √n so that x² ≥ n
    x = math.isqrt(n) + 1

    while True:
        # Step 2 — compute the candidate y² = x² − n
        y_squared = x * x - n

        # Step 3 — check whether y² is a perfect square
        y = is_perfect_square(y_squared)
        if y is not None:
            # Found x² − y² = n  →  factors are (x−y) and (x+y)
            return (x - y, x + y)

        # Step 4 — increment x and retry
        x += 1


# ---------------------------------------------------------------------------
# Weak RSA key generation (p and q intentionally close)
# ---------------------------------------------------------------------------

def generate_weak_rsa_keypair(bit_size=64):
    """
    Generate an RSA key pair whose primes p and q are close together,
    making the modulus vulnerable to Fermat's factorization.

    Parameters
    ----------
    bit_size : int
        Approximate bit-length of each prime (default: 64).

    Returns
    -------
    tuple[RSA, int, int]
        Configured RSA instance, true p, true q.
    """
    rsa = RSA()
    # Generate p first, then restrict q to a narrow band just above p
    # so that |p − q| ≪ √n — exactly the weakness Fermat exploits.
    p = rsa.primary_nb_generator(2**(bit_size - 1), 2**bit_size)
    q = rsa.primary_nb_generator(p, p + 2**(bit_size // 2))   # q ≈ p

    # key_generator returns (n, e, d) without storing them on self
    n, e, d = rsa.key_generator(p, q)
    rsa.setKeys(d, e, n)
    return rsa, p, q


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    print("=" * 60)
    print("   Fermat's Factorization Attack on a Weak RSA Key")
    print("=" * 60)

    # --- 1. Build a weak RSA instance -----------------------------------
    print("\n[1] Generating weak RSA key pair (p ≈ q) …")
    rsa, true_p, true_q = generate_weak_rsa_keypair(bit_size=2048)
    n = rsa.n

    print(f"    p = {true_p}")
    print(f"    q = {true_q}")
    print(f"    n = {n}")
    print(f"    |p − q| = {abs(true_p - true_q)}")

    # --- 2. Attack: factor n without knowing p or q ---------------------
    print("\n[2] Running Fermat's factorization on n …")
    found_p, found_q = fermat_factor(n)

    print(f"    Recovered p = {found_p}")
    print(f"    Recovered q = {found_q}")

    # --- 3. Verify the recovered factors --------------------------------
    print("\n[3] Verification")
    factors_correct = (found_p * found_q == n)
    match_true      = (sorted([found_p, found_q]) == sorted([true_p, true_q]))

    print(f"    p × q == n  →  {factors_correct}")
    print(f"    Matches true primes  →  {match_true}")

    # --- 4. Exploit: reconstruct the private key and decrypt ------------
    print("\n[4] Reconstructing private key from recovered factors …")
    phi_n    = (found_p - 1) * (found_q - 1)
    # d = e⁻¹ mod φ(n)  via the extended Euclidean algorithm already in RSA
    _, d, _  = rsa.Euclide(rsa.public_key, phi_n)
    d        = d % phi_n

    message  = 314159265358979          # arbitrary plaintext
    cipher   = rsa.encrypt(message)
    recovered = rsa.fast_exp(cipher, d, n)

    print(f"    Original message  : {message}")
    print(f"    Ciphertext        : {cipher}")
    print(f"    Decrypted message : {recovered}")
    print(f"    Attack succeeded  → {recovered == message}")
    print()
