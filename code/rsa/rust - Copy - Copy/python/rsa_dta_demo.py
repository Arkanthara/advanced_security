"""Simple RSA timing attack and Fermat factorization demo.

The sample collection is server-like: for each message, the attacker only sees
the total time taken by RSA decryption with the private exponent d.
"""

from __future__ import annotations

import argparse
import math
import random
import time
from dataclasses import dataclass

import gmpy2 as gmpy


@dataclass
class RsaKey:
    """RSA key material."""

    n: int
    e: int
    d: int
    p: int
    q: int


@dataclass
class Sample:
    """One server timing sample."""

    message: int
    elapsed_ns: float


def generate_rsa_key(key_bits: int, rng: random.Random) -> RsaKey:
    """Generate an RSA key with close primes.

    Parameters
    ----------
    key_bits : int
        Bit size of the modulus n.
    rng : random.Random
        Random generator.

    Returns
    -------
    RsaKey
        Generated RSA key.
    """
    prime_bits = key_bits // 2

    while True:
        p = generate_prime(prime_bits, rng)
        q = int(gmpy.next_prime(p + close_prime_gap(prime_bits, rng)))

        if p == q or p.bit_length() != prime_bits or q.bit_length() != prime_bits:
            continue

        n = p * q
        if n.bit_length() != key_bits:
            continue

        phi = (p - 1) * (q - 1)
        e = choose_public_exponent(phi, rng)
        d = mod_inverse(e, phi)
        return RsaKey(n=n, e=e, d=d, p=p, q=q)


def generate_prime(bits: int, rng: random.Random) -> int:
    """Generate a prime with gmpy2.

    Parameters
    ----------
    bits : int
        Prime bit size.
    rng : random.Random
        Random generator.

    Returns
    -------
    int
        Prime number.
    """
    candidate = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
    return int(gmpy.next_prime(candidate))


def close_prime_gap(prime_bits: int, rng: random.Random) -> int:
    """Return a small odd gap so Fermat factorization is fast."""
    gap_bits = min(max(prime_bits // 4, 8), 20)
    return rng.getrandbits(gap_bits) | 1


def choose_public_exponent(phi: int, rng: random.Random) -> int:
    """Choose a prime e coprime with phi(n)."""
    exponent_bits = min(32, phi.bit_length() - 1)

    while True:
        e = int(gmpy.next_prime(max(3, rng.getrandbits(exponent_bits) | 1)))
        if 1 < e < phi and math.gcd(e, phi) == 1:
            return e


def collect_samples(key: RsaKey, sample_count: int, reps: int, rng: random.Random) -> list[Sample]:
    """Collect total decryption timings from the server.

    Parameters
    ----------
    key : RsaKey
        Secret RSA key used by the server.
    sample_count : int
        Number of messages to time.
    reps : int
        Number of repeated decryptions per message.
    rng : random.Random
        Random generator.

    Returns
    -------
    list[Sample]
        Pairs ``(message, total_decryption_time)``.
    """
    samples = []

    for _ in range(sample_count):
        message = rng.randrange(2, key.n - 1)
        start = time.perf_counter_ns()

        for _ in range(reps):
            square_and_multiply(message, key.d, key.n)

        elapsed = (time.perf_counter_ns() - start) / reps
        samples.append(Sample(message=message, elapsed_ns=elapsed))

    return samples


def timing_attack(samples: list[Sample], n: int, d_bits: int, recover_bits: int) -> int:
    """Recover low bits of d with a correlation timing attack.

    The right-to-left algorithm always performs the same square sequence,
    independent of d. The attacker estimates that common square cost and removes
    it, then correlates the remaining timing with the branch-dependent multiply
    cost for H0 and H1.

    Parameters
    ----------
    samples : list[Sample]
        Server timings.
    n : int
        RSA modulus.
    d_bits : int
        Bit length of d.
    recover_bits : int
        Number of low bits to recover.

    Returns
    -------
    int
        Recovered low-bit prefix of d.
    """
    scale = calibrate_cost_scale(n)
    branch_timings = [
        sample.elapsed_ns - scale * estimate_square_cost(sample.message, n, d_bits)
        for sample in samples
    ]
    recovered = 0

    print("DTA timing attack")
    print("Samples contain only total server decryption time.")
    print("The known square cost is removed before correlating H0 and H1.\n")

    for bit_index in range(recover_bits):
        h0 = recovered
        h1 = recovered | (1 << bit_index)
        costs0 = [
            estimate_multiply_prefix_cost(sample.message, n, h0, bit_index + 1)
            for sample in samples
        ]
        costs1 = [
            estimate_multiply_prefix_cost(sample.message, n, h1, bit_index + 1)
            for sample in samples
        ]
        corr0 = abs(pearson(branch_timings, costs0))
        corr1 = abs(pearson(branch_timings, costs1))
        guess = 1 if corr1 > corr0 else 0

        if guess:
            recovered |= 1 << bit_index

        print(
            f"bit {bit_index:>4}: "
            f"corr(H0)={corr0:>8.5f} corr(H1)={corr1:>8.5f} -> {guess}"
        )

    return recovered


def square_and_multiply(base: int, exponent: int, n: int) -> int:
    """Compute ``base**exponent mod n`` with vulnerable square-and-multiply.

    Parameters
    ----------
    base : int
        Input message.
    exponent : int
        Secret exponent.
    n : int
        RSA modulus.

    Returns
    -------
    int
        Decryption result.
    """
    result = 1
    power = base % n

    while exponent > 0:
        if exponent & 1:
            result = mul_mod_plain(result, power, n)
        power = mul_mod_plain(power, power, n)
        exponent >>= 1

    return result


def mul_mod_plain(a: int, b: int, n: int) -> int:
    """Compute ``(a * b) % n`` with plain double-and-add multiplication."""
    result = 0
    addend = a % n

    while b > 0:
        if b & 1:
            result = (result + addend) % n
        addend = (addend << 1) % n
        b >>= 1

    return result


def estimate_square_cost(message: int, n: int, bits: int) -> float:
    """Estimate the common square cost for a full decryption."""
    power = message % n
    cost = 0.0

    for _ in range(bits):
        cost += multiply_cost(power, power)
        power = mul_mod_plain(power, power, n)

    return cost


def estimate_multiply_prefix_cost(message: int, n: int, prefix: int, bits: int) -> float:
    """Estimate branch-dependent multiply cost for the first ``bits`` bits."""
    result = 1
    power = message % n
    cost = 0.0

    for bit_index in range(bits):
        if (prefix >> bit_index) & 1:
            cost += multiply_cost(result, power)
            result = mul_mod_plain(result, power, n)
        power = mul_mod_plain(power, power, n)

    return cost


def multiply_cost(a: int, b: int) -> float:
    """Estimate the operation count of ``mul_mod_plain(a, b, n)``.

    Parameters
    ----------
    a : int
        First operand.
    b : int
        Second operand.

    Returns
    -------
    float
        Simple cost estimate for double-and-add multiplication.
    """
    return float(max(1, b.bit_length()) + max(1, b.bit_count()) * max(1, a.bit_length()))


def calibrate_cost_scale(n: int, trials: int = 50) -> float:
    """Estimate nanoseconds per cost unit for the local multiplication.

    Parameters
    ----------
    n : int
        RSA modulus.
    trials : int
        Number of local calibration multiplications.

    Returns
    -------
    float
        Linear scale converting estimated cost units to nanoseconds.
    """
    rng = random.Random(0xC0FFEE)
    costs = []
    times = []

    for _ in range(trials):
        a = rng.randrange(2, n - 1)
        b = rng.randrange(2, n - 1)
        start = time.perf_counter_ns()
        mul_mod_plain(a, b, n)
        times.append(time.perf_counter_ns() - start)
        costs.append(multiply_cost(a, b))

    mean_cost = sum(costs) / trials
    mean_time = sum(times) / trials
    covariance = sum((c - mean_cost) * (t - mean_time) for c, t in zip(costs, times))
    variance = sum((c - mean_cost) ** 2 for c in costs)
    return covariance / variance if variance else mean_time / mean_cost


def fermat_factor(n: int) -> tuple[int, int, int]:
    """Factor n with Fermat factorization.

    Parameters
    ----------
    n : int
        RSA modulus.

    Returns
    -------
    tuple[int, int, int]
        Factors p, q and number of iterations.
    """
    x = math.isqrt(n)
    if x * x < n:
        x += 1

    steps = 0
    while True:
        y2 = x * x - n
        y = math.isqrt(y2)
        if y * y == y2:
            return x - y, x + y, steps
        x += 1
        steps += 1


def recover_private_key_with_fermat(n: int, e: int) -> tuple[int, int, int, int, int]:
    """Recover p, q, phi(n), and d from n and e."""
    p, q, steps = fermat_factor(n)
    phi = (p - 1) * (q - 1)
    d = mod_inverse(e, phi)
    return p, q, phi, d, steps


def extended_euclid(a: int, b: int) -> tuple[int, int, int]:
    """Return gcd(a, b) and Bezout coefficients."""
    r0, r1 = a, b
    s0, s1 = 1, 0
    t0, t1 = 0, 1

    while r1:
        q = r0 // r1
        r0, r1 = r1, r0 - q * r1
        s0, s1 = s1, s0 - q * s1
        t0, t1 = t1, t0 - q * t1

    return r0, s0, t0


def mod_inverse(a: int, modulus: int) -> int:
    """Return ``a^-1 mod modulus``."""
    gcd, x, _ = extended_euclid(a, modulus)
    if gcd != 1:
        raise ValueError("inverse does not exist")
    return x % modulus


def pearson(xs: list[float], ys: list[float]) -> float:
    """Compute Pearson correlation."""
    mean_x = sum(xs) / len(xs)
    mean_y = sum(ys) / len(ys)
    covariance = 0.0
    variance_x = 0.0
    variance_y = 0.0

    for x, y in zip(xs, ys):
        dx = x - mean_x
        dy = y - mean_y
        covariance += dx * dy
        variance_x += dx * dx
        variance_y += dy * dy

    if variance_x == 0.0 or variance_y == 0.0:
        return 0.0

    return covariance / math.sqrt(variance_x * variance_y)


def bit_string_lsb_first(value: int, bits: int) -> str:
    """Return the first ``bits`` bits, least significant bit first."""
    return "".join("1" if (value >> bit) & 1 else "0" for bit in range(bits))


def count_matching_low_bits(a: int, b: int, bits: int) -> int:
    """Count equal low bits in two integers."""
    return sum(((a >> bit) & 1) == ((b >> bit) & 1) for bit in range(bits))


def parse_int(value: str) -> int:
    """Parse decimal or 0x-prefixed integers."""
    return int(value, 0)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=200)
    parser.add_argument("--reps", type=int, default=1)
    parser.add_argument("--recover-bits", type=int, default=12)
    parser.add_argument("--key-bits", type=int, default=128)
    parser.add_argument("--seed", type=parse_int, default=0x1234567890ABCDEF)
    return parser.parse_args()


def main() -> None:
    """Run the demo."""
    args = parse_args()

    if args.samples < 2 or args.reps < 1:
        raise SystemExit("--samples must be >= 2 and --reps must be >= 1")
    if args.key_bits < 32 or args.key_bits % 2 or args.recover_bits < 1:
        raise SystemExit("--key-bits must be even and >= 32; --recover-bits must be >= 1")

    rng = random.Random(args.seed)
    key = generate_rsa_key(args.key_bits, rng)

    if args.recover_bits > key.d.bit_length():
        raise SystemExit(f"--recover-bits must be <= d bits ({key.d.bit_length()})")

    print("\nRSA server-style timing demo")
    print(
        f"samples={args.samples}, reps={args.reps}, "
        f"recover_bits={args.recover_bits}, key_bits={args.key_bits}"
    )
    print(f"n bits = {key.n.bit_length()}")
    print(f"e      = {key.e}")
    print(f"d bits = {key.d.bit_length()}")
    print("prime generator = gmpy2.next_prime\n")

    samples = collect_samples(key, args.samples, args.reps, rng)
    recovered = timing_attack(samples, key.n, key.d.bit_length(), args.recover_bits)
    correct = count_matching_low_bits(key.d, recovered, args.recover_bits)

    print(f"\nDTA result on the first {args.recover_bits} low bits of d")
    print(f"recovered = {bit_string_lsb_first(recovered, args.recover_bits)}")
    print(f"real      = {bit_string_lsb_first(key.d, args.recover_bits)}")
    print(f"correct   = {correct}/{args.recover_bits}")

    fp, fq, _, recovered_d, steps = recover_private_key_with_fermat(key.n, key.e)
    factors_match = (fp, fq) == (key.p, key.q) or (fp, fq) == (key.q, key.p)

    print("\nFermat key recovery from n and e")
    print(f"steps          = {steps}")
    print(f"factors match  = {factors_match}")
    print(f"recovered d ok = {recovered_d == key.d}")


if __name__ == "__main__":
    main()
