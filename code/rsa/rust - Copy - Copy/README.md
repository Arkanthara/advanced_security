# RSA Timing and Fermat Demo

Small Rust demo for two RSA weaknesses:

- a right-to-left square-and-multiply timing leak on the private exponent `d`
- Fermat factorization when `p` and `q` are generated close together

The demo generates a simple RSA key:

```text
n = p * q
phi(n) = (p - 1) * (q - 1)
e = a generated odd value coprime with phi(n)
d = e^-1 mod phi(n), found with extended Euclid
```

The timed exponentiation uses `num-bigint::BigUint` and a deliberately plain
double-and-add modular multiplication. This keeps the multiplication behavior
simple for teaching the side channel.

On non-MSVC targets, primes are generated with Rug's `next_prime`. Rug's GMP
backend does not support the Windows MSVC target used by this workspace, so the
code falls back there to a small Miller-Rabin generator built on `num-bigint`.

Run:

```powershell
cargo run -- [samples] [reps] [recover_bits] [key_bits]
```

Example:

```powershell
cargo run -- 100 1 12 128
```

Arguments:

```text
samples       number of input messages to time, at least 2
reps          repeated timings per sample, at least 1
recover_bits  low bits of d to recover with DTA
key_bits      RSA modulus size, for example 128, 512, 1024, 2048
```

The exponentiation scans `d` from least significant bit to most significant bit,
so the DTA output is shown low-bit first. Larger keys and larger recovered
prefixes need more samples or repetitions because the correlation signal is
statistical.
