# Square-and-Multiply Timing Demo

Minimal Rust demo for the branch leak in square-and-multiply:

```text
if current exponent bit == 1:
    r = (r * y) mod n    extra direct multiplication
y = (y * y) mod n        always executed
```

When a secret exponent bit is `1`, the loop does one extra multiplication. When it is `0`, it skips that multiplication. Repeating the measurement many times makes this branch-dependent timing difference visible.

This version intentionally stays small:

- pure Rust code
- `num-bigint::BigUint` only for fixed-size large integers
- direct multiplication only: `(&r * &y) % n`
- supports bit sizes up to `4096`
- no artificial delay
- no custom multiplication
- no constant-time tricks
- compiler optimization disabled in `Cargo.toml`

Run:

```powershell
cargo run -- 40 20 16 1 512
```

Arguments:

```text
cargo run -- [samples] [reps] [recover_bits] [known_bits] [bit_size<=4096]
```

Examples:

```powershell
cargo run -- 40 20 16 1 512
cargo run -- 30 10 12 1 1024
cargo run -- 20 6 8 1 2048
cargo run -- 10 3 6 1 4096
```

The reference loop reads the exponent from least significant bit to most significant bit, so `known_bits` means known low bits.

Because this uses real direct big-integer multiplication with no artificial delay, results are naturally noisy. Increase `samples` and `reps` if a bit is misclassified.

