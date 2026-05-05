# Square-and-Multiply Timing Demo

Minimal Rust demo for the branch leak in square-and-multiply:

```text
if current exponent bit == 1:
    r = (r * y) mod n    extra direct multiplication
y = (y * y) mod n        always executed
```

When a secret exponent bit is `1`, the loop does one extra multiplication. When it is `0`, it skips that multiplication. Repeating the measurement many times makes this branch-dependent timing difference visible.

This version intentionally stays small:

- pure Rust, no big-integer crate
- fixed-size `u128` arithmetic
- direct multiplication only: `(a * b) % n`
- `bit_size <= 64`, so products fit inside `u128`
- no artificial delay, no custom multiplication, no constant-time tricks
- compiler optimization disabled in `Cargo.toml`

Run:

```powershell
cargo run -- 100 200 16 1 32
```

Arguments:

```text
cargo run -- [samples] [reps] [recover_bits] [known_bits] [bit_size<=64]
```

The reference loop reads the exponent from least significant bit to most significant bit, so `known_bits` means known low bits.

Because this uses real direct multiplication with no artificial delay, results are naturally noisier. Increase `samples` and `reps` if a bit is misclassified.

