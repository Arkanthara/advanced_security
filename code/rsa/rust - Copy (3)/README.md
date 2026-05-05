# Square-and-Multiply Timing Demo

Minimal Rust demo for timing leakage in branchy square-and-multiply RSA exponentiation.

The program now builds an RSA-like key:

```text
p, q probable prime
n = p * q
phi(n) = (p - 1) * (q - 1)
e = 65537, with gcd(e, phi(n)) = 1
d = e^-1 mod phi(n), found with extended Euclid
```

The vulnerable operation is still only:

```text
if current exponent bit == 1:
    r = (r * y) mod n    extra direct BigUint multiplication
y = (y * y) mod n        always executed
```

For each sample `y`, the reference time is the full exponentiation `y^d mod n`, repeated according to `reps`. For each target bit, the attack tests two prefix hypotheses, `bit = 0` and `bit = 1`, and chooses the one with lower residual variance.

Run:

```powershell
cargo run -- 100 3 6 1 2048
```

Arguments:

```text
cargo run -- [samples] [reps] [recover_bits] [known_bits] [bit_size<=4096]
```

Examples:

```powershell
cargo run -- 40 3 8 1 512
cargo run -- 60 3 8 1 1024
cargo run -- 100 3 6 1 2048
cargo run -- 80 2 4 1 4096
```

Prime search uses a small Miller-Rabin probable-prime test, which is enough for this timing demo.

This uses real `BigUint` multiplication with no artificial delay and no custom multiplication, so the full-timing attack is naturally noisy. Increase `samples` and `reps` when a bit is misclassified.
