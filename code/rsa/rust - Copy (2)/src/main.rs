use num_bigint::BigUint;
use std::hint::black_box;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let samples = arg(&args, 1, 40);
    let reps = arg(&args, 2, 20);
    let recover_bits = arg(&args, 3, 16);
    let known_bits = arg(&args, 4, 1);
    let bit_size = arg(&args, 5, 512);

    if !(8..=4096).contains(&bit_size) || known_bits + recover_bits > bit_size {
        eprintln!(
            "usage: cargo run -- [samples] [reps] [recover_bits] [known_bits] [bit_size<=4096]"
        );
        std::process::exit(1);
    }

    let one = BigUint::from(1u8);
    let n = (&one << bit_size) - BigUint::from(159u16);

    let mut rng = 0x1234_5678_90ab_cdefu128;
    let mut random = |bits: usize| {
        let mut bytes = vec![0u8; bits.div_ceil(8)];
        for byte in &mut bytes {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            rng ^= rng << 29;
            rng ^= rng >> 17;
            *byte = rng as u8;
        }
        BigUint::from_bytes_be(&bytes)
    };

    let mut secret = random(bit_size) % &n;
    secret.set_bit(0, true);
    secret.set_bit((bit_size - 1) as u64, true);

    let bases: Vec<BigUint> = (0..samples)
        .map(|_| BigUint::from(2u8) + (random(bit_size) % (&n - BigUint::from(3u8))))
        .collect();

    let known_mask = if known_bits == 0 {
        BigUint::from(0u8)
    } else {
        (&one << known_bits) - &one
    };
    let mut recovered = &secret & known_mask;

    println!("\nSquare-and-Multiply timing demo");
    println!("samples={samples}, reps={reps}, recover_bits={recover_bits}, known_bits={known_bits}, bit_size={bit_size}");
    println!("n has {} bits", n.bits());
    println!("secret x has {} bits", secret.bits());
    println!("known low bits: {}\n", {
        (0..known_bits)
            .map(|i| if recovered.bit(i as u64) { '1' } else { '0' })
            .collect::<String>()
    });

    println!("The branch `if x & 1 == 1` performs one extra direct BigUint multiplication.");
    println!(
        "For each bit, the demo times the secret branch and compares bit=0 vs bit=1 hypotheses.\n"
    );

    for bit_index in known_bits..known_bits + recover_bits {
        let mut t0 = Vec::with_capacity(samples);
        let mut t1 = Vec::with_capacity(samples);
        let mut r0 = Vec::with_capacity(samples);
        let mut r1 = Vec::with_capacity(samples);

        for y in &bases {
            let real_bit = secret.bit(bit_index as u64);
            let oracle = time_step(y, &secret, bit_index, real_bit, &n, reps);
            let h0 = time_step(y, &recovered, bit_index, false, &n, reps);
            let h1 = time_step(y, &recovered, bit_index, true, &n, reps);

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

        let guess = err1 < err0;
        if guess {
            recovered.set_bit(bit_index as u64, true);
        }

        let real = secret.bit(bit_index as u64);
        let ok = if guess == real { "correct" } else { "wrong" };

        println!(
            "bit {bit_index:>4}: H0 avg={avg0:>9.1}ns err={err0:>9.1} var={var0:>12.1} | H1 avg={avg1:>9.1}ns err={err1:>9.1} var={var1:>12.1} -> {} ({ok}, real {})",
            guess as u8,
            real as u8
        );
    }

    let total = known_bits + recover_bits;
    let guessed_bits = (0..total)
        .map(|i| if recovered.bit(i as u64) { '1' } else { '0' })
        .collect::<String>();
    let real_bits = (0..total)
        .map(|i| if secret.bit(i as u64) { '1' } else { '0' })
        .collect::<String>();
    let correct = (0..total)
        .filter(|&i| secret.bit(i as u64) == recovered.bit(i as u64))
        .count();

    println!("\nrecovered low {total} bits:");
    println!("  guessed = {guessed_bits}");
    println!("  real    = {real_bits}");
    println!("  correct = {correct}/{total}");

    black_box(square_and_multiply(&BigUint::from(7u8), &secret, &n));
}

fn square_and_multiply(y: &BigUint, x: &BigUint, n: &BigUint) -> BigUint {
    let mut r = BigUint::from(1u8);
    let mut y = y % n;
    let mut x = x.clone();

    while x != BigUint::from(0u8) {
        if x.bit(0) {
            r = (&r * &y) % n;
        }
        x >>= 1usize;
        y = (&y * &y) % n;
    }

    r
}

fn time_step(
    y: &BigUint,
    prefix: &BigUint,
    bit_index: usize,
    bit: bool,
    n: &BigUint,
    reps: usize,
) -> f64 {
    let mut r = BigUint::from(1u8);
    let mut y = y % n;
    let mut x = prefix.clone();

    for _ in 0..bit_index {
        if x.bit(0) {
            r = (&r * &y) % n;
        }
        x >>= 1usize;
        y = (&y * &y) % n;
    }

    let start = Instant::now();
    let mut out = BigUint::from(0u8);
    for _ in 0..reps {
        let mut rr = black_box(r.clone());
        let mut yy = black_box(y.clone());
        if bit {
            rr = (&rr * &yy) % n;
        }
        yy = (&yy * &yy) % n;
        out ^= rr ^ yy;
    }
    black_box(out);

    start.elapsed().as_nanos() as f64 / reps as f64
}

fn arg(args: &[String], i: usize, default: usize) -> usize {
    args.get(i).and_then(|s| s.parse().ok()).unwrap_or(default)
}
