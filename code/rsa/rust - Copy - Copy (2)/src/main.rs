//! # Timing DPA on square-and-multiply exponentiation
//!
//! Simulates an attacker that can only observe the **total** time taken by a
//! server to compute `base^secret mod n` — as if querying a decryption oracle.
//!
//! ## Attack strategy
//!
//! For each unknown bit at position `k`, we test two hypotheses:
//!   - H₀: bit k = 0
//!   - H₁: bit k = 1
//!
//! For every collected timing sample (one per base), we estimate a **cost** for
//! each hypothesis by simulating the prefix steps up to bit `k` and computing
//! the Hamming weight of the accumulator `r`.  Using Hamming weight as a timing
//! proxy is a classical side-channel leakage model: more active bits lead to
//! more partial products in the modular multiplication, causing slight timing
//! differences.  Crucially the cost **varies across samples** (each base gives
//! different intermediate values), which is what makes Pearson correlation useful.
//!
//! The hypothesis whose cost vector has the **highest Pearson correlation** with
//! the measured timings is chosen as the recovered bit.
//!
//! ## Usage
//!
//!   cargo run -- [samples] [reps] [recover_bits] [known_bits] [bit_size≤64]
//!
//! Defaults: samples=300, reps=500, recover_bits=16, known_bits=1, bit_size=32

use std::hint::black_box;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let samples      = arg(&args, 1, 300);
    let reps         = arg(&args, 2, 500);
    let recover_bits = arg(&args, 3, 16);
    let known_bits   = arg(&args, 4, 1);
    let bit_size     = arg(&args, 5, 32);

    if !(8..=64).contains(&bit_size) || known_bits + recover_bits > bit_size {
        eprintln!("usage: cargo run -- [samples] [reps] [recover_bits] [known_bits] [bit_size<=64]");
        std::process::exit(1);
    }

    let mask = (1u128 << bit_size) - 1;
    let n    = mask - 58; // odd modulus slightly below 2^bit_size
    let mut rng = 0x1234_5678_90ab_cdefu128;
    let mut rand = || {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
        rng ^= rng << 29;
        rng ^= rng >> 17;
        rng
    };

    // Secret exponent: odd, with the high bit set (simulates a typical RSA key)
    let secret = (rand() & mask) | 1 | (1u128 << (bit_size - 1));

    // One random base per sample — these are the "messages" sent to the server
    let bases: Vec<u128> = (0..samples).map(|_| 2 + rand() % (n - 3)).collect();

    println!("\nSquare-and-multiply timing DPA");
    println!("samples={samples}  reps={reps}  recover_bits={recover_bits}  known_bits={known_bits}  bit_size={bit_size}");
    println!("n={n}  secret={secret}\n");

    // ── Phase 1: collect oracle timings ────────────────────────────────────────
    // Measure the total time for base_i^secret mod n for each sample.
    // An attacker can observe this but nothing else about the computation.
    let timings: Vec<f64> = bases.iter()
        .map(|&y| time_full(y, secret, n, reps))
        .collect();

    // ── Phase 2: recover bits via DPA ──────────────────────────────────────────
    // Seed with the known low bits (e.g. the LSB is always 1 for an odd secret)
    let mut recovered = secret & ((1u128 << known_bits) - 1);

    for bit_index in known_bits..known_bits + recover_bits {
        // Build a cost vector for each hypothesis.
        // cost[i] is the estimated computation cost for base_i under that hypothesis.
        let cost = |b: u8| -> Vec<f64> {
            bases.iter().map(|&y| hw_cost(y, recovered, bit_index, b, n)).collect()
        };

        let c0 = cost(0);
        let c1 = cost(1);

        // The hypothesis whose cost profile best tracks the oracle timings wins.
        let r0 = pearson(&timings, &c0);
        let r1 = pearson(&timings, &c1);
        let guess = if r1 > r0 { 1u8 } else { 0u8 };

        if guess == 1 { recovered |= 1u128 << bit_index; }

        let real = ((secret >> bit_index) & 1) as u8;
        let ok   = if guess == real { "✓" } else { "✗" };
        println!(
            "bit {bit_index:>2}:  r(H0)={r0:>+.4}  r(H1)={r1:>+.4}  → guess={guess}  real={real}  {ok}"
        );
    }

    // ── Summary ────────────────────────────────────────────────────────────────
    let total   = known_bits + recover_bits;
    let correct = (0..total).filter(|&i| ((secret >> i) & 1) == ((recovered >> i) & 1)).count();
    let fmt     = |v: u128| (0..total).map(|i| if (v >> i) & 1 == 1 { '1' } else { '0' }).collect::<String>();
    println!("\nrecovered {total} bits:");
    println!("  guessed = {}", fmt(recovered));
    println!("  real    = {}", fmt(secret));
    println!("  correct = {correct}/{total}");
}

// ── Core functions ─────────────────────────────────────────────────────────────

/// **Oracle**: time `reps` calls to `base^exp mod n`, return mean nanoseconds.
///
/// This is the only measurement available to the attacker — the full server
/// round-trip time.  Individual steps are hidden.
fn time_full(base: u128, exp: u128, n: u128, reps: usize) -> f64 {
    let start = Instant::now();
    for _ in 0..reps {
        black_box(square_and_multiply(black_box(base), exp, n));
    }
    start.elapsed().as_nanos() as f64 / reps as f64
}

/// **Cost model**: Hamming weight of the accumulator `r` at step `bit_index`
/// under the hypothesis that the exponent bit at `bit_index` equals `bit`.
///
/// Steps 0..bit_index are replayed using the known `prefix` bits.
/// The hypothesis bit is then applied, and `r.count_ones()` is returned.
///
/// Why Hamming weight?  In software modular multiplication, more set bits
/// in the operands mean more partial-product additions, causing measurable
/// timing differences.  Because the intermediate `r` depends on the base `y`,
/// the cost varies across samples — a prerequisite for Pearson correlation.
fn hw_cost(base: u128, prefix: u128, bit_index: usize, bit: u8, n: u128) -> f64 {
    let mut r = 1u128;
    let mut y = base % n;
    let mut x = prefix;

    // Replay the known prefix bits to reach the state just before bit_index
    for _ in 0..bit_index {
        if x & 1 == 1 { r = (r * y) % n; }
        x >>= 1;
        y = (y * y) % n;
    }

    // Apply the hypothesised bit
    if bit == 1 { r = (r * y) % n; }

    r.count_ones() as f64 // Hamming weight as timing proxy
}

/// **Pearson correlation coefficient** between two equal-length slices.
///
/// Returns a value in [−1, 1].  A higher positive value indicates that the
/// cost model and the timings vary together — i.e., the hypothesis is likely
/// correct.  Returns 0 if either slice is constant (zero variance).
fn pearson(x: &[f64], y: &[f64]) -> f64 {
    let n  = x.len() as f64;
    let mx = x.iter().sum::<f64>() / n;
    let my = y.iter().sum::<f64>() / n;

    let cov: f64 = x.iter().zip(y).map(|(xi, yi)| (xi - mx) * (yi - my)).sum();
    let sx:  f64 = x.iter().map(|xi| (xi - mx).powi(2)).sum::<f64>().sqrt();
    let sy:  f64 = y.iter().map(|yi| (yi - my).powi(2)).sum::<f64>().sqrt();

    if sx == 0.0 || sy == 0.0 { return 0.0; }
    cov / (sx * sy)
}

/// Standard square-and-multiply modular exponentiation: `base^exp mod n`.
fn square_and_multiply(base: u128, mut exp: u128, n: u128) -> u128 {
    let mut r = 1u128;
    let mut y = base % n;
    while exp > 0 {
        if exp & 1 == 1 { r = (r * y) % n; }
        exp >>= 1;
        y = (y * y) % n;
    }
    r
}

/// Parse `args[i]` as `usize`, falling back to `default`.
fn arg(args: &[String], i: usize, default: usize) -> usize {
    args.get(i).and_then(|s| s.parse().ok()).unwrap_or(default)
}
