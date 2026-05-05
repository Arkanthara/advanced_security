use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, Zero};
use std::hint::black_box;
use std::time::Instant;

#[cfg(not(target_env = "msvc"))]
use rug::Integer;
#[cfg(not(target_env = "msvc"))]
use std::str::FromStr;

struct RsaKey {
    n: BigUint,
    e: BigUint,
    d: BigUint,
    p: BigUint,
    q: BigUint,
}

struct TimingSample {
    message: BigUint,
    step_nanos: Vec<f64>,
}

struct SimpleRng {
    state: u64,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let samples = arg(&args, 1, 200);
    let reps = arg(&args, 2, 1);
    let recover_bits = arg(&args, 3, 12);
    let key_bits = arg(&args, 4, 128);

    if key_bits < 32 || key_bits % 2 != 0 || recover_bits == 0 || samples < 2 || reps == 0 {
        eprintln!("usage: cargo run -- [samples] [reps] [recover_bits] [key_bits]");
        eprintln!("example: cargo run --release -- 400 2 64 128");
        std::process::exit(1);
    }

    let mut rng = SimpleRng::new(0x1234_5678_90ab_cdef);
    let key = generate_rsa_key(key_bits, &mut rng);
    if recover_bits > key.d.bits() as usize {
        eprintln!("recover_bits must be <= d bits ({})", key.d.bits());
        std::process::exit(1);
    }

    println!("\nRSA square-and-multiply timing demo");
    println!("samples={samples}, reps={reps}, recover_bits={recover_bits}, key_bits={key_bits}");
    println!("n bits = {}", key.n.bits());
    println!("e      = {}", key.e);
    println!("d bits = {}", key.d.bits());
    println!("prime generator = {}", prime_generator_name());
    println!("p and q are close so Fermat factorization finishes quickly.\n");

    let samples = collect_samples(&key, samples, reps, recover_bits, &mut rng);
    let recovered = timing_attack(&samples, &key.n, recover_bits);

    let correct_bits = count_matching_low_bits(&key.d, &recovered, recover_bits);
    println!("\nDTA result on the first {recover_bits} low bits of d");
    println!(
        "recovered = {}",
        bit_string_lsb_first(&recovered, recover_bits)
    );
    println!("real      = {}", bit_string_lsb_first(&key.d, recover_bits));
    println!("correct   = {correct_bits}/{recover_bits}");

    let (fp, fq, fermat_steps) = fermat_factor(&key.n);
    let phi = (&fp - BigUint::one()) * (&fq - BigUint::one());
    let recovered_d = mod_inverse(&key.e, &phi);

    println!("\nFermat key recovery from n and e");
    println!("steps          = {fermat_steps}");
    println!(
        "factors match  = {}",
        fp == key.p && fq == key.q || fp == key.q && fq == key.p
    );
    println!("recovered d ok = {}", recovered_d == key.d);

    black_box(square_and_multiply(&BigUint::from(7u32), &key.d, &key.n));
}

fn generate_rsa_key(key_bits: usize, rng: &mut SimpleRng) -> RsaKey {
    let prime_bits = key_bits / 2;

    loop {
        let p = generate_prime(prime_bits, rng);
        let q = next_prime_after(&(&p + BigUint::from(close_prime_gap(prime_bits, rng))));
        if p == q || p.bits() != prime_bits as u64 || q.bits() != prime_bits as u64 {
            continue;
        }

        let n = &p * &q;
        if n.bits() != key_bits as u64 {
            continue;
        }

        let phi = (&p - BigUint::one()) * (&q - BigUint::one());
        let e = choose_public_exponent(&phi, rng);
        let d = mod_inverse(&e, &phi);

        return RsaKey { n, e, d, p, q };
    }
}

#[cfg(not(target_env = "msvc"))]
fn generate_prime(bits: usize, rng: &mut SimpleRng) -> BigUint {
    let mut candidate = random_biguint(bits, rng);
    candidate |= BigUint::one();

    let mut prime = biguint_to_rug(&candidate);
    prime.next_prime_mut();
    rug_to_biguint(&prime)
}

#[cfg(not(target_env = "msvc"))]
fn next_prime_after(candidate: &BigUint) -> BigUint {
    let mut prime = biguint_to_rug(candidate);
    prime.next_prime_mut();
    rug_to_biguint(&prime)
}

#[cfg(target_env = "msvc")]
fn generate_prime(bits: usize, rng: &mut SimpleRng) -> BigUint {
    let mut candidate = random_biguint(bits, rng) | BigUint::one();

    loop {
        if is_probable_prime(&candidate) {
            return candidate;
        }

        candidate += 2u32;
        if candidate.bits() != bits as u64 {
            candidate = random_biguint(bits, rng) | BigUint::one();
        }
    }
}

#[cfg(target_env = "msvc")]
fn next_prime_after(candidate: &BigUint) -> BigUint {
    let mut prime = candidate | BigUint::one();

    while !is_probable_prime(&prime) {
        prime += 2u32;
    }

    prime
}

fn close_prime_gap(prime_bits: usize, rng: &mut SimpleRng) -> u64 {
    let gap_bits = prime_bits.saturating_div(4).clamp(8, 20);
    let mask = (1u64 << gap_bits) - 1;
    (rng.next_u64() & mask) | 1
}

fn choose_public_exponent(phi: &BigUint, rng: &mut SimpleRng) -> BigUint {
    loop {
        let candidate = (rng.next_u64() as u32) | 1;
        let e = BigUint::from(candidate.max(3));
        if gcd(e.clone(), phi.clone()) == BigUint::one() {
            return e;
        }
    }
}

fn collect_samples(
    key: &RsaKey,
    sample_count: usize,
    reps: usize,
    attack_bits: usize,
    rng: &mut SimpleRng,
) -> Vec<TimingSample> {
    let mut samples = Vec::with_capacity(sample_count);

    for _ in 0..sample_count {
        let message = random_message(&key.n, rng);
        let mut step_nanos = Vec::with_capacity(attack_bits);

        for bit in 0..attack_bits {
            let (result, power) = state_after_prefix(&message, &key.d, &key.n, bit);
            let secret_bit = key.d.bit(bit as u64);
            let start = Instant::now();

            for _ in 0..reps {
                let out = square_and_multiply_step(
                    black_box(&result),
                    black_box(&power),
                    secret_bit,
                    black_box(&key.n),
                );
                black_box(out);
            }

            step_nanos.push(start.elapsed().as_nanos() as f64 / reps as f64);
        }

        samples.push(TimingSample {
            message,
            step_nanos,
        });
    }

    samples
}

fn timing_attack(samples: &[TimingSample], n: &BigUint, recover_bits: usize) -> BigUint {
    let mut recovered = BigUint::zero();

    println!("DTA timing attack");
    println!("Each hypothesis estimates the prefix cost, then uses Pearson correlation.\n");

    for bit in 0..recover_bits {
        let timings: Vec<f64> = samples
            .iter()
            .map(|sample| sample.step_nanos[bit])
            .collect();
        let h0 = recovered.clone();
        let h1 = &recovered | (BigUint::one() << bit);

        let costs0 = estimate_costs(samples, n, &h0, bit, false);
        let costs1 = estimate_costs(samples, n, &h1, bit, true);
        let corr0 = pearson(&timings, &costs0).abs();
        let corr1 = pearson(&timings, &costs1).abs();

        let guess = if corr1 > corr0 { 1u8 } else { 0u8 };
        if guess == 1 {
            recovered |= BigUint::one() << bit;
        }

        println!("bit {bit:>4}: corr(H0)={corr0:>8.5} corr(H1)={corr1:>8.5} -> {guess}");
    }

    recovered
}

fn estimate_costs(
    samples: &[TimingSample],
    n: &BigUint,
    prefix: &BigUint,
    bit: usize,
    bit_value: bool,
) -> Vec<f64> {
    samples
        .iter()
        .map(|sample| estimate_step_cost(&sample.message, prefix, bit, bit_value, n))
        .collect()
}

fn estimate_step_cost(
    base: &BigUint,
    prefix: &BigUint,
    bit: usize,
    bit_value: bool,
    n: &BigUint,
) -> f64 {
    let (result, power) = state_after_prefix(base, prefix, n, bit);
    let mut cost = 0.0;

    if bit_value {
        cost += multiply_cost(&result, &power);
    }
    cost += multiply_cost(&power, &power);

    cost
}

// Cost model for mul_mod_plain: one scan over multiplier bits, plus additions for 1 bits.
fn multiply_cost(a: &BigUint, b: &BigUint) -> f64 {
    let scan_cost = b.bits().max(1);
    let add_cost = hamming_weight(b).max(1) * a.bits().max(1);
    (scan_cost + add_cost) as f64
}

fn square_and_multiply(base: &BigUint, exponent: &BigUint, n: &BigUint) -> BigUint {
    square_and_multiply_prefix(base, exponent, n, exponent.bits() as usize)
}

fn square_and_multiply_prefix(
    base: &BigUint,
    exponent: &BigUint,
    n: &BigUint,
    bits: usize,
) -> BigUint {
    let mut result = BigUint::one();
    let mut power = base % n;
    let bits = bits.min(exponent.bits() as usize);

    for bit in 0..bits {
        if exponent.bit(bit as u64) {
            result = mul_mod_plain(&result, &power, n);
        }
        power = mul_mod_plain(&power, &power, n);
    }

    result
}

fn state_after_prefix(
    base: &BigUint,
    exponent_prefix: &BigUint,
    n: &BigUint,
    bits: usize,
) -> (BigUint, BigUint) {
    let mut result = BigUint::one();
    let mut power = base % n;

    for bit in 0..bits {
        if exponent_prefix.bit(bit as u64) {
            result = mul_mod_plain(&result, &power, n);
        }
        power = mul_mod_plain(&power, &power, n);
    }

    (result, power)
}

fn square_and_multiply_step(
    result: &BigUint,
    power: &BigUint,
    bit: bool,
    n: &BigUint,
) -> (BigUint, BigUint) {
    let mut result = result.clone();
    if bit {
        result = mul_mod_plain(&result, power, n);
    }
    let power = mul_mod_plain(power, power, n);

    (result, power)
}

fn mul_mod_plain(a: &BigUint, b: &BigUint, n: &BigUint) -> BigUint {
    let mut result = BigUint::zero();
    let mut addend = a % n;

    for bit in 0..b.bits() {
        if b.bit(bit) {
            result += &addend;
            result %= n;
        }

        addend <<= 1usize;
        addend %= n;
    }

    result
}

fn fermat_factor(n: &BigUint) -> (BigUint, BigUint, usize) {
    let mut x = ceil_sqrt(n);
    let mut steps = 0usize;

    loop {
        let y2 = (&x * &x) - n;
        if let Some(y) = exact_sqrt(&y2) {
            return (&x - &y, &x + &y, steps);
        }

        x += BigUint::one();
        steps += 1;
    }
}

fn ceil_sqrt(n: &BigUint) -> BigUint {
    let root = integer_sqrt(n);
    if &root * &root == *n {
        root
    } else {
        root + BigUint::one()
    }
}

fn exact_sqrt(n: &BigUint) -> Option<BigUint> {
    let root = integer_sqrt(n);
    if &root * &root == *n {
        Some(root)
    } else {
        None
    }
}

fn integer_sqrt(n: &BigUint) -> BigUint {
    if *n <= BigUint::one() {
        return n.clone();
    }

    let mut x = BigUint::one() << n.bits().div_ceil(2);
    loop {
        let y = (&x + n / &x) >> 1usize;
        if y >= x {
            return x;
        }
        x = y;
    }
}

fn mod_inverse(a: &BigUint, modulus: &BigUint) -> BigUint {
    let a = BigInt::from_biguint(Sign::Plus, a.clone());
    let modulus_i = BigInt::from_biguint(Sign::Plus, modulus.clone());
    let (g, x, _) = extended_euclid(a, modulus_i.clone());
    assert_eq!(g, BigInt::one(), "e and phi(n) must be coprime");

    let positive = ((x % &modulus_i) + &modulus_i) % &modulus_i;
    positive.to_biguint().unwrap()
}

fn extended_euclid(a: BigInt, b: BigInt) -> (BigInt, BigInt, BigInt) {
    let mut r0 = a;
    let mut r1 = b;
    let mut s0 = BigInt::one();
    let mut s1 = BigInt::zero();
    let mut t0 = BigInt::zero();
    let mut t1 = BigInt::one();

    while !r1.is_zero() {
        let q = &r0 / &r1;
        (r0, r1) = (r1.clone(), r0 - &q * r1);
        (s0, s1) = (s1.clone(), s0 - &q * s1);
        (t0, t1) = (t1.clone(), t0 - q * t1);
    }

    (r0, s0, t0)
}

fn gcd(mut a: BigUint, mut b: BigUint) -> BigUint {
    while !b.is_zero() {
        let r = a % &b;
        a = b;
        b = r;
    }
    a
}

#[cfg(target_env = "msvc")]
fn is_probable_prime(n: &BigUint) -> bool {
    let two = BigUint::from(2u32);
    let three = BigUint::from(3u32);
    if *n < two {
        return false;
    }
    if *n == two || *n == three {
        return true;
    }
    if !n.bit(0) {
        return false;
    }

    let small_primes = [3u32, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
    for prime in small_primes {
        let p = BigUint::from(prime);
        if n == &p {
            return true;
        }
        if n % &p == BigUint::zero() {
            return false;
        }
    }

    let one = BigUint::one();
    let n_minus_one = n - &one;
    let mut d = n_minus_one.clone();
    let mut shifts = 0u32;
    while !d.bit(0) {
        d >>= 1usize;
        shifts += 1;
    }

    let bases = [2u32, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
    'base_loop: for base in bases {
        let a = BigUint::from(base) % n;
        if a.is_zero() {
            continue;
        }

        let mut x = a.modpow(&d, n);
        if x == one || x == n_minus_one {
            continue;
        }

        for _ in 1..shifts {
            x = (&x * &x) % n;
            if x == n_minus_one {
                continue 'base_loop;
            }
        }

        return false;
    }

    true
}

fn random_message(n: &BigUint, rng: &mut SimpleRng) -> BigUint {
    loop {
        let message = random_biguint(n.bits() as usize, rng) % n;
        if message > BigUint::one() {
            return message;
        }
    }
}

fn random_biguint(bits: usize, rng: &mut SimpleRng) -> BigUint {
    let byte_count = bits.div_ceil(8);
    let mut bytes = vec![0u8; byte_count];
    rng.fill_bytes(&mut bytes);

    let top_bits = bits % 8;
    if top_bits == 0 {
        bytes[byte_count - 1] |= 0x80;
    } else {
        let mask = (1u8 << top_bits) - 1;
        bytes[byte_count - 1] &= mask;
        bytes[byte_count - 1] |= 1u8 << (top_bits - 1);
    }

    BigUint::from_bytes_le(&bytes)
}

fn hamming_weight(x: &BigUint) -> u64 {
    x.to_bytes_le()
        .iter()
        .map(|byte| byte.count_ones() as u64)
        .sum()
}

#[cfg(not(target_env = "msvc"))]
fn biguint_to_rug(x: &BigUint) -> Integer {
    Integer::from_str(&x.to_str_radix(10)).unwrap()
}

#[cfg(not(target_env = "msvc"))]
fn rug_to_biguint(x: &Integer) -> BigUint {
    BigUint::parse_bytes(x.to_string().as_bytes(), 10).unwrap()
}

fn pearson(xs: &[f64], ys: &[f64]) -> f64 {
    let n = xs.len() as f64;
    let mean_x = xs.iter().sum::<f64>() / n;
    let mean_y = ys.iter().sum::<f64>() / n;
    let mut covariance = 0.0;
    let mut variance_x = 0.0;
    let mut variance_y = 0.0;

    for (x, y) in xs.iter().zip(ys) {
        let dx = x - mean_x;
        let dy = y - mean_y;
        covariance += dx * dy;
        variance_x += dx * dx;
        variance_y += dy * dy;
    }

    if variance_x == 0.0 || variance_y == 0.0 {
        0.0
    } else {
        covariance / (variance_x.sqrt() * variance_y.sqrt())
    }
}

fn count_matching_low_bits(a: &BigUint, b: &BigUint, bits: usize) -> usize {
    (0..bits)
        .filter(|bit| a.bit(*bit as u64) == b.bit(*bit as u64))
        .count()
}

fn bit_string_lsb_first(x: &BigUint, bits: usize) -> String {
    (0..bits)
        .map(|bit| if x.bit(bit as u64) { '1' } else { '0' })
        .collect()
}

fn arg(args: &[String], i: usize, default: usize) -> usize {
    args.get(i).and_then(|s| s.parse().ok()).unwrap_or(default)
}

#[cfg(not(target_env = "msvc"))]
fn prime_generator_name() -> &'static str {
    "Rug next_prime"
}

#[cfg(target_env = "msvc")]
fn prime_generator_name() -> &'static str {
    "num-bigint Miller-Rabin fallback because Rug/GMP does not support MSVC"
}

impl SimpleRng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.state ^= self.state >> 21;
        self.state ^= self.state << 35;
        self.state ^= self.state >> 4;
        self.state
    }

    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        for chunk in bytes.chunks_mut(8) {
            let random = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&random[..chunk.len()]);
        }
    }
}
