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
    let beam_width = arg(&args, 6, 8);

    if !(32..=4096).contains(&bit_size) || samples == 0 || reps == 0 || beam_width == 0 {
        eprintln!(
            "usage: cargo run -- [samples] [reps] [recover_bits] [known_bits] [bit_size<=4096] [beam_width]"
        );
        std::process::exit(1);
    }

    let mut rng = 0x1234_5678_90ab_cdefu128;
    println!("\nGenerating RSA-like key...");
    let (n, phi, e, d) = generate_rsa_key(bit_size, &mut rng);
    let d_bits = d.bits() as usize;

    let target_bits = known_bits + recover_bits;
    let seeded_known_bits = if known_bits == 0 && target_bits > 0 {
        1
    } else {
        known_bits
    };

    if target_bits > d_bits {
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
    let known_mask = if seeded_known_bits == 0 {
        BigUint::from(0u8)
    } else {
        (&one << seeded_known_bits) - &one
    };
    let mut recovered = &d & known_mask;
    let mut candidates = vec![(recovered.clone(), 0.0)];

    println!("Square-and-Multiply timing attack");
    println!("samples={samples}, reps={reps}, recover_bits={recover_bits}, known_bits={known_bits}, bit_size={bit_size}, beam_width={beam_width}");
    if seeded_known_bits > known_bits {
        println!("RSA gives bit 0 for free: d is odd, so d[0] = 1");
    }
    println!("known low bits: {}\n", {
        (0..seeded_known_bits)
            .map(|i| if recovered.bit(i as u64) { '1' } else { '0' })
            .collect::<String>()
    });

    for bit_index in seeded_known_bits..target_bits {
        let mut next_candidates = Vec::with_capacity(candidates.len() * 2);

        for (prefix, score) in &candidates {
            for guess in [false, true] {
                let mut hypothesis = prefix.clone();
                hypothesis.set_bit(bit_index as u64, guess);

                let mut avg = 0.0;
                let mut residuals = Vec::with_capacity(samples);

                for (i, y) in bases.iter().enumerate() {
                    let t = measure_exponentiation(y, &hypothesis, &n, reps, bit_index + 1);
                    avg += t;
                    residuals.push(reference[i] - t);
                }

                avg /= samples as f64;
                let mean = residuals.iter().sum::<f64>() / samples as f64;
                let var = residuals
                    .iter()
                    .map(|v| (v - mean) * (v - mean))
                    .sum::<f64>()
                    / samples as f64;

                next_candidates.push((hypothesis, guess, avg, var, score + var));
            }
        }

        let best0 = next_candidates
            .iter()
            .filter(|(_, guess, _, _, _)| !*guess)
            .min_by(|a, b| a.4.total_cmp(&b.4))
            .unwrap();
        let best1 = next_candidates
            .iter()
            .filter(|(_, guess, _, _, _)| *guess)
            .min_by(|a, b| a.4.total_cmp(&b.4))
            .unwrap();
        let best0_avg = best0.2;
        let best0_var = best0.3;
        let best1_avg = best1.2;
        let best1_var = best1.3;

        next_candidates.sort_by(|a, b| a.4.total_cmp(&b.4));
        candidates = next_candidates
            .into_iter()
            .take(beam_width)
            .map(|(candidate, _, _, _, score)| (candidate, score))
            .collect();
        recovered = candidates[0].0.clone();

        let guess = recovered.bit(bit_index as u64);
        let real = d.bit(bit_index as u64);
        let ok = if guess == real { "correct" } else { "wrong" };
        let mask = (&one << (bit_index + 1)) - &one;
        let real_prefix = &d & mask;
        let in_beam = candidates
            .iter()
            .any(|(candidate, _)| candidate == &real_prefix);

        println!(
            "bit {bit_index:>4}: H0 avg={:>10.1}ns var={:>14.1} | H1 avg={:>10.1}ns var={:>14.1} -> {} ({ok}, real {}, true_prefix_in_beam={in_beam})",
            best0_avg,
            best0_var,
            best1_avg,
            best1_var,
            guess as u8,
            real as u8
        );
    }

    let total = target_bits;
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
