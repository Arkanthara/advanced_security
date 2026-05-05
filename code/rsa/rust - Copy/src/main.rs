use std::hint::black_box;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let samples = arg(&args, 1, 100);
    let reps = arg(&args, 2, 200);
    let recover_bits = arg(&args, 3, 16);
    let known_bits = arg(&args, 4, 1);
    let bit_size = arg(&args, 5, 32);

    if !(8..=64).contains(&bit_size) || known_bits + recover_bits > bit_size {
        eprintln!(
            "usage: cargo run -- [samples] [reps] [recover_bits] [known_bits] [bit_size<=64]"
        );
        std::process::exit(1);
    }

    let mask = (1u128 << bit_size) - 1;
    let n = mask - 58;
    let mut rng = 0x1234_5678_90ab_cdefu128;
    let mut next_rand = || {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
        rng ^= rng << 29;
        rng ^= rng >> 17;
        rng
    };

    let secret = (next_rand() & mask) | 1 | (1u128 << (bit_size - 1));
    let bases: Vec<u128> = (0..samples).map(|_| 2 + (next_rand() % (n - 3))).collect();
    let mut recovered = secret & ((1u128 << known_bits) - 1);

    println!("\nSquare-and-Multiply timing demo");
    println!("samples={samples}, reps={reps}, recover_bits={recover_bits}, known_bits={known_bits}, bit_size={bit_size}");
    println!("n={n}");
    println!("secret x={secret}");
    println!("known low bits: {}\n", {
        (0..known_bits)
            .map(|i| {
                if ((recovered >> i) & 1) == 1 {
                    '1'
                } else {
                    '0'
                }
            })
            .collect::<String>()
    });

    println!("The branch `if x & 1 == 1` performs one extra direct multiplication.");
    println!(
        "For each bit, the demo times the secret branch and compares bit=0 vs bit=1 hypotheses.\n"
    );

    for bit_index in known_bits..known_bits + recover_bits {
        let mut t0 = Vec::with_capacity(samples);
        let mut t1 = Vec::with_capacity(samples);
        let mut r0 = Vec::with_capacity(samples);
        let mut r1 = Vec::with_capacity(samples);

        for &y in &bases {
            let real_bit = ((secret >> bit_index) & 1) as u8;
            let oracle = time_step(y, secret, bit_index, real_bit, n, reps);
            let h0 = time_step(y, recovered, bit_index, 0, n, reps);
            let h1 = time_step(y, recovered, bit_index, 1, n, reps);

            t0.push(h0);
            t1.push(h1);
            r0.push(oracle - h0);
            r1.push(oracle - h1);
        }

        let avg0 = t0.iter().sum::<f64>() / samples as f64;
        let avg1 = t1.iter().sum::<f64>() / samples as f64;
        let err0 = r0.iter().map(|v| v.abs()).sum::<f64>() / samples as f64;
        let err1 = r1.iter().map(|v| v.abs()).sum::<f64>() / samples as f64;
        let mean0 = r0.iter().sum::<f64>() / samples as f64;
        let mean1 = r1.iter().sum::<f64>() / samples as f64;
        let var0 = r0.iter().map(|v| (v - mean0) * (v - mean0)).sum::<f64>() / samples as f64;
        let var1 = r1.iter().map(|v| (v - mean1) * (v - mean1)).sum::<f64>() / samples as f64;

        let guess = if err1 < err0 { 1u8 } else { 0u8 };
        if guess == 1 {
            recovered |= 1u128 << bit_index;
        }

        let real = ((secret >> bit_index) & 1) as u8;
        let ok = if guess == real { "correct" } else { "wrong" };

        println!(
            "bit {bit_index:>2}: H0 avg={avg0:>7.1}ns err={err0:>7.1} var={var0:>10.1} | H1 avg={avg1:>7.1}ns err={err1:>7.1} var={var1:>10.1} -> {guess} ({ok}, real {real})"
        );
    }

    let total = known_bits + recover_bits;
    let guessed_bits = (0..total)
        .map(|i| {
            if ((recovered >> i) & 1) == 1 {
                '1'
            } else {
                '0'
            }
        })
        .collect::<String>();
    let real_bits = (0..total)
        .map(|i| if ((secret >> i) & 1) == 1 { '1' } else { '0' })
        .collect::<String>();
    let correct = (0..total)
        .filter(|&i| ((secret >> i) & 1) == ((recovered >> i) & 1))
        .count();

    println!("\nrecovered low {total} bits:");
    println!("  guessed = {guessed_bits}");
    println!("  real    = {real_bits}");
    println!("  correct = {correct}/{total}");

    black_box(square_and_multiply(7, secret, n));
}

fn square_and_multiply(y: u128, mut x: u128, n: u128) -> u128 {
    let mut r = 1u128;
    let mut y = y % n;

    while x > 0 {
        if (x & 1) == 1 {
            r = (r * y) % n;
        }
        x >>= 1;
        y = (y * y) % n;
    }

    r
}

fn time_step(y: u128, prefix: u128, bit_index: usize, bit: u8, n: u128, reps: usize) -> f64 {
    let mut r = 1u128;
    let mut y = y % n;
    let mut x = prefix;

    for _ in 0..bit_index {
        if (x & 1) == 1 {
            r = (r * y) % n;
        }
        x >>= 1;
        y = (y * y) % n;
    }

    let start = Instant::now();
    let mut out = 0u128;
    for _ in 0..reps {
        let mut rr = black_box(r);
        let mut yy = black_box(y);
        if bit == 1 {
            rr = (rr * yy) % n;
        }
        yy = (yy * yy) % n;
        out ^= rr ^ yy;
    }
    black_box(out);

    start.elapsed().as_nanos() as f64 / reps as f64
}

fn arg(args: &[String], i: usize, default: usize) -> usize {
    args.get(i).and_then(|s| s.parse().ok()).unwrap_or(default)
}
