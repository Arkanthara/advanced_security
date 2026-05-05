use num_bigint::{BigInt, BigUint, Sign};
use std::hint::black_box;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let samples = arg(&args, 1, 30);
    let reps = arg(&args, 2, 3);
    let recover_bits = arg(&args, 3, 12);
    let known_bits = arg(&args, 4, 1);
    let bit_size = arg(&args, 5, 512);

    if !(32..=4096).contains(&bit_size) {
        eprintln!(
            "usage: cargo run -- [samples] [reps] [recover_bits] [known_bits] [bit_size<=4096]"
        );
        std::process::exit(1);
    }

    let mut rng = 0x1234_5678_90ab_cdefu128;
    println!("\nGenerating RSA-like key...");
    let (n, phi, e, d) = generate_rsa_key(bit_size, &mut rng);
    let d_bits = d.bits() as usize;

    if known_bits + recover_bits > d_bits {
        eprintln!("known_bits + recover_bits must fit in d, which has {d_bits} bits");
        std::process::exit(1);
    }

    let bases: Vec<BigUint> = (0..samples)
        .map(|_| {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            let y_bits = 2 + (rng as usize % (bit_size - 2));
            BigUint::from(2u8) + (random_biguint(y_bits, &mut rng) % (&n - 3u8))
        })
        .collect();

    println!("n has {} bits", n.bits());
    println!("e = {e}");
    println!("d has {d_bits} bits");
    println!("(e * d) mod phi(n) = {}", (&e * &d) % &phi);
    println!("Collecting full reference timings: y^d mod n\n");

    let reference: Vec<f64> = bases
        .iter()
        .map(|y| measure_exponentiation(y, &d, &n, reps, d_bits))
        .collect();

    let one = BigUint::from(1u8);
    let known_mask = if known_bits == 0 {
        BigUint::from(0u8)
    } else {
        (&one << known_bits) - &one
    };
    let mut recovered = &d & known_mask;

    println!("Square-and-Multiply timing attack");
    println!("samples={samples}, reps={reps}, recover_bits={recover_bits}, known_bits={known_bits}, bit_size={bit_size}");
    println!("known low bits: {}\n", {
        (0..known_bits)
            .map(|i| if recovered.bit(i as u64) { '1' } else { '0' })
            .collect::<String>()
    });

    for bit_index in known_bits..known_bits + recover_bits {
        let h0 = recovered.clone();
        let mut h1 = recovered.clone();
        h1.set_bit(bit_index as u64, true);

        let mut residual0 = Vec::with_capacity(samples);
        let mut residual1 = Vec::with_capacity(samples);
        let mut avg0 = 0.0;
        let mut avg1 = 0.0;

        for (i, y) in bases.iter().enumerate() {
            let t0 = measure_exponentiation(y, &h0, &n, reps, bit_index + 1);
            let t1 = measure_exponentiation(y, &h1, &n, reps, bit_index + 1);
            avg0 += t0;
            avg1 += t1;
            residual0.push(reference[i] - t0);
            residual1.push(reference[i] - t1);
        }

        avg0 /= samples as f64;
        avg1 /= samples as f64;
        let mean0 = residual0.iter().sum::<f64>() / samples as f64;
        let mean1 = residual1.iter().sum::<f64>() / samples as f64;
        let var0 = residual0
            .iter()
            .map(|v| (v - mean0) * (v - mean0))
            .sum::<f64>()
            / samples as f64;
        let var1 = residual1
            .iter()
            .map(|v| (v - mean1) * (v - mean1))
            .sum::<f64>()
            / samples as f64;

        let guess = var1 < var0;
        if guess {
            recovered.set_bit(bit_index as u64, true);
        }

        let real = d.bit(bit_index as u64);
        let ok = if guess == real { "correct" } else { "wrong" };

        println!(
            "bit {bit_index:>4}: H0 avg={avg0:>10.1}ns var={var0:>14.1} | H1 avg={avg1:>10.1}ns var={var1:>14.1} -> {} ({ok}, real {})",
            guess as u8,
            real as u8
        );
    }

    let total = known_bits + recover_bits;
    let guessed_bits = (0..total)
        .map(|i| if recovered.bit(i as u64) { '1' } else { '0' })
        .collect::<String>();
    let real_bits = (0..total)
        .map(|i| if d.bit(i as u64) { '1' } else { '0' })
        .collect::<String>();
    let correct = (0..total)
        .filter(|&i| d.bit(i as u64) == recovered.bit(i as u64))
        .count();

    println!("\nrecovered low {total} bits of d:");
    println!("  guessed = {guessed_bits}");
    println!("  real    = {real_bits}");
    println!("  correct = {correct}/{total}");

    black_box(square_and_multiply(&BigUint::from(7u8), &d, &n));
}

fn generate_rsa_key(bit_size: usize, rng: &mut u128) -> (BigUint, BigUint, BigUint, BigUint) {
    let one = BigUint::from(1u8);
    let e = BigUint::from(65_537u32);

    loop {
        let p = random_prime(bit_size / 2, rng);
        let q = random_prime(bit_size - bit_size / 2, rng);
        if p == q {
            continue;
        }

        let n = &p * &q;
        if n.bits() != bit_size as u64 {
            continue;
        }

        let phi = (&p - &one) * (&q - &one);
        let (gcd, d) = extended_euclid(&e, &phi);
        if gcd == one {
            return (n, phi, e, d);
        }
    }
}

fn random_prime(bits: usize, rng: &mut u128) -> BigUint {
    loop {
        let mut candidate = random_biguint(bits, rng);
        candidate.set_bit((bits - 1) as u64, true);
        candidate.set_bit(0, true);

        if probably_prime(&candidate) {
            return candidate;
        }
    }
}

fn probably_prime(n: &BigUint) -> bool {
    let one = BigUint::from(1u8);
    let two = BigUint::from(2u8);
    let small_primes = [2u16, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];

    if n < &two {
        return false;
    }
    for p in small_primes {
        let p = BigUint::from(p);
        if n == &p {
            return true;
        }
        if (n % &p) == BigUint::from(0u8) {
            return false;
        }
    }

    let n_minus_one = n - &one;
    let mut odd_part = n_minus_one.clone();
    let mut powers_of_two = 0usize;
    while !odd_part.bit(0) {
        odd_part >>= 1usize;
        powers_of_two += 1;
    }

    for base in [2u16, 3, 5, 7, 11] {
        let base = BigUint::from(base);
        if base >= n_minus_one {
            continue;
        }

        let mut x = square_and_multiply(&base, &odd_part, n);
        let mut passes = x == one || x == n_minus_one;
        for _ in 1..powers_of_two {
            x = (&x * &x) % n;
            if x == n_minus_one {
                passes = true;
                break;
            }
        }
        if !passes {
            return false;
        }
    }

    true
}

fn extended_euclid(a: &BigUint, b: &BigUint) -> (BigUint, BigUint) {
    let mut r0 = BigInt::from_biguint(Sign::Plus, b.clone());
    let mut r1 = BigInt::from_biguint(Sign::Plus, a.clone());
    let mut t0 = BigInt::from(0u8);
    let mut t1 = BigInt::from(1u8);

    while r1 != BigInt::from(0u8) {
        let q = &r0 / &r1;
        (r0, r1) = (r1.clone(), r0 - &q * r1);
        (t0, t1) = (t1.clone(), t0 - q * t1);
    }

    let modulus = BigInt::from_biguint(Sign::Plus, b.clone());
    let inverse = ((t0 % &modulus) + &modulus) % &modulus;
    (r0.to_biguint().unwrap(), inverse.to_biguint().unwrap())
}

fn random_biguint(bits: usize, rng: &mut u128) -> BigUint {
    let mut bytes = vec![0u8; bits.div_ceil(8)];
    for byte in &mut bytes {
        *rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
        *rng ^= *rng << 29;
        *rng ^= *rng >> 17;
        *byte = *rng as u8;
    }

    BigUint::from_bytes_be(&bytes) % (BigUint::from(1u8) << bits)
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

fn measure_exponentiation(y: &BigUint, x: &BigUint, n: &BigUint, reps: usize, steps: usize) -> f64 {
    let start = Instant::now();
    let mut out = BigUint::from(0u8);

    for _ in 0..reps {
        let mut r = BigUint::from(1u8);
        let mut y = black_box(y % n);
        let mut x = black_box(x.clone());

        for _ in 0..steps {
            if x.bit(0) {
                r = (&r * &y) % n;
            }
            x >>= 1usize;
            y = (&y * &y) % n;
        }

        out ^= r;
    }

    black_box(out);
    start.elapsed().as_nanos() as f64 / reps as f64
}

fn arg(args: &[String], i: usize, default: usize) -> usize {
    args.get(i).and_then(|s| s.parse().ok()).unwrap_or(default)
}
