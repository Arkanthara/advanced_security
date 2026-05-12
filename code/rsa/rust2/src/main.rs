//! RSA encryption + timing attack (square-and-multiply variance method).
//!
//! Dependencies (Cargo.toml):
//!   num-bigint = { version = "0.4", features = ["rand"] }
//!   num-traits  = "0.2"
//!   rand        = "0.8"

use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
use num_traits::{One, Zero};
use rand::thread_rng;
use std::time::Instant;

// ── Primality (Miller–Rabin, 25 rounds) ──────────────────────────────────────

fn is_prime(n: &BigUint) -> bool {
    if n < &BigUint::from(4u32) {
        return n >= &BigUint::from(2u32);
    }
    if n % 2u32 == BigUint::zero() {
        return false;
    }

    // Write n−1 = 2^r · d
    let n1 = n - BigUint::one();
    let mut d = n1.clone();
    let mut r = 0u32;
    while &d % 2u32 == BigUint::zero() {
        d >>= 1;
        r += 1;
    }

    let mut rng = thread_rng();
    'witness: for _ in 0..25 {
        let a = rng.gen_biguint_range(&BigUint::from(2u32), &n1);
        let mut x = a.modpow(&d, n);
        if x == BigUint::one() || x == n1 {
            continue;
        }
        for _ in 1..r {
            x = x.modpow(&BigUint::from(2u32), n);
            if x == n1 {
                continue 'witness;
            }
        }
        return false;
    }
    true
}

fn gen_prime(bits: u64) -> BigUint {
    let mut rng = thread_rng();
    loop {
        // Ensure exactly `bits` bits and odd
        let p = rng.gen_biguint(bits) | (BigUint::one() << (bits - 1)) | BigUint::one();
        if is_prime(&p) {
            return p;
        }
    }
}

// ── RSA ──────────────────────────────────────────────────────────────────────

struct Rsa {
    e: BigUint,
    d: BigUint,
    n: BigUint,
}

/// Extended-Euclidean modular inverse of `a` mod `m`.
fn mod_inverse(a: &BigUint, m: &BigUint) -> BigUint {
    let (mut r0, mut r1) = (m.to_bigint().unwrap(), a.to_bigint().unwrap());
    let (mut s0, mut s1) = (BigInt::zero(), BigInt::one());
    while !r1.is_zero() {
        let q = &r0 / &r1;
        (r0, r1) = (r1.clone(), &r0 - &q * &r1);
        (s0, s1) = (s1.clone(), &s0 - &q * &s1);
    }
    let m = m.to_bigint().unwrap();
    ((s0 % &m + &m) % &m).to_biguint().unwrap()
}

impl Rsa {
    /// Build RSA from explicit p, q, e (all user-supplied).
    fn from_pqe(p: &BigUint, q: &BigUint, e: &BigUint) -> Self {
        let n = p * q;
        let phi = (p - BigUint::one()) * (q - BigUint::one());
        Rsa { e: e.clone(), d: mod_inverse(e, &phi), n }
    }

    /// Generate a fresh RSA key-pair with `bits`-bit modulus (e = 65537).
    fn generate(bits: u64) -> Self {
        Self::from_pqe(&gen_prime(bits / 2), &gen_prime(bits / 2), &BigUint::from(65537u32))
    }

    fn encrypt(&self, m: &BigUint) -> BigUint { m.modpow(&self.e, &self.n) }
    fn decrypt(&self, c: &BigUint) -> BigUint { c.modpow(&self.d, &self.n) }

    /// Decrypt with an arbitrary key prefix (used by the attack).
    fn decrypt_with(&self, c: &BigUint, key: &BigUint) -> BigUint { c.modpow(key, &self.n) }
}

// ── Timing attack ─────────────────────────────────────────────────────────────

/// Collect `n_samples` min-timing measurements (ns) for random ciphertexts.
///
/// Taking the minimum over `n_reps` removes OS-jitter noise (Kocher 1996):
/// interrupts can only ADD latency, so the minimum best estimates true cost.
///
/// `label` is printed as a progress prefix, e.g. "  server" or "  hyp[bit=1]".
fn collect_samples(rsa: &Rsa, key: &BigUint, n_samples: usize, n_reps: usize, label: &str) -> Vec<u64> {
    let mut rng = thread_rng();
    let print_every = (n_samples / 10).max(1);   // print ~10 updates

    let samples = (0..n_samples)
        .map(|i| {
            if i % print_every == 0 {
                print!("\r  {label}: {}/{n_samples}", i + 1);
                use std::io::Write;
                let _ = std::io::stdout().flush();
            }
            let c = rng.gen_biguint_range(&BigUint::one(), &rsa.n);
            (0..n_reps)
                .map(|_| {
                    let t = Instant::now();
                    let _ = rsa.decrypt_with(&c, key);
                    t.elapsed().as_nanos() as u64
                })
                .min()
                .unwrap()
        })
        .collect();

    println!("\r  {label}: {n_samples}/{n_samples} ✓");
    samples
}

/// Variance of element-wise differences between two timing traces.
///
/// When a key-hypothesis prefix matches the real key, the decryption timing
/// patterns align and Var(server_time − hyp_time) drops — that's our signal.
fn variance_of_diff(a: &[u64], b: &[u64]) -> f64 {
    let diffs: Vec<f64> = a.iter().zip(b).map(|(&x, &y)| x as f64 - y as f64).collect();
    let mean = diffs.iter().sum::<f64>() / diffs.len() as f64;
    diffs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / diffs.len() as f64
}

/// Recover `n_iters` key bits above the `known_bits` LSBs using beam search.
///
/// At each step two candidates (bit=0, bit=1) are tried for every key in the
/// beam; the `beam` hypotheses with lowest timing variance are kept.
fn timing_attack(
    rsa: &Rsa,
    n_samples: usize,
    n_reps: usize,
    n_iters: usize,
    known_bits: usize,
    beam: usize,
) {
    println!("[server reference]");
    let server = collect_samples(rsa, &rsa.d, n_samples, n_reps, "server");

    // Seed the beam with the known LSBs.
    let init = &rsa.d & ((BigUint::one() << known_bits) - BigUint::one());
    let mut candidates: Vec<(BigUint, f64)> = vec![(init, f64::INFINITY); beam];

    for i in 0..n_iters {
        println!("\n[iter {:>2}/{n_iters}]", i + 1);
        let mut next: Vec<(BigUint, f64)> = Vec::new();

        for (key, _) in &candidates {
            for &set_bit in &[false, true] {
                let hyp = if set_bit {
                    key | (BigUint::one() << (known_bits + i))
                } else {
                    key.clone()
                };
                let label = format!("hyp bit={}", set_bit as u8);
                let times = collect_samples(rsa, &hyp, n_samples, n_reps, &label);
                next.push((hyp, variance_of_diff(&server, &times)));
            }
        }

        next.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
        next.truncate(beam);

        // Result for this iteration.
        let (best, best_var) = &next[0];
        let bit  = (best >> (known_bits + i))   & BigUint::one();
        let real = (&rsa.d >> (known_bits + i)) & BigUint::one();
        println!(
            "  → bit={bit}  var={best_var:.2e}  {}",
            if bit == real { "✓ correct" } else { "✗ wrong" }
        );

        candidates = next;
    }

    // Final summary.
    println!("\n{}", "─".repeat(40));
    for (rank, (key, var)) in candidates.iter().enumerate() {
        let mask    = (BigUint::one() << n_iters) - BigUint::one();
        let guessed = (key >> known_bits)    & &mask;
        let real    = (&rsa.d >> known_bits) & &mask;
        let errors: u32 = (guessed ^ &real).to_bytes_be().iter().map(|b| b.count_ones()).sum();
        println!(
            "Candidate #{}: var={var:.2e}  errors={errors}/{n_iters}",
            rank + 1
        );
    }
}

// ── main ──────────────────────────────────────────────────────────────────────

fn main() {
    // ── Verify against the known Python test vectors ─────────────────────────
    let p = BigUint::parse_bytes(b"13109499994810966779468866046493465498469807493634236479294124421385342920350717814807375283698575766763256101470694189234369358996750113963585617491399169", 10).unwrap();
    let q = BigUint::parse_bytes(b"9497561827984502554523100157901534504433126034087863778629488755692649311435921364240405549590851856701860175924335776598684751639633322074428628372725777", 10).unwrap();
    let e = BigUint::from(4_574_830_074_548_708_213_u64);
    let m = BigUint::from(123_456_789_132_456_789_u64);

    let rsa = Rsa::from_pqe(&p, &q, &e);

    let d_expected = BigUint::parse_bytes(b"1685394382767324790326942621450485552187209875614438478305225564629345944620726038114923060947436330701451901921041511234432041036987266468290187679773130363479895993621867708066144608084390089775045890165825736468637468786667820591136139480545376198614216373031208691260339805721685482401743494212035728605", 10).unwrap();
    let c_expected = BigUint::parse_bytes(b"32468932964181322647810913060097066975304467072050643211304428656476623133068329653886195740426516038144100129255895281039142864272296799126753030014464755203797098445143314298922512718785433009136404533290100525054356166805463645892708927694801117827432767298393815743170470207262077229267156532545837844746", 10).unwrap();

    assert_eq!(rsa.d, d_expected,  "private key mismatch");
    let cipher = rsa.encrypt(&m);
    assert_eq!(cipher,    c_expected, "ciphertext mismatch");
    assert_eq!(rsa.decrypt(&cipher), m, "decryption mismatch");

    println!("=============== RSA OK ===============");
    println!("message:    {m}");
    println!("ciphertext: {cipher}");
    println!("decrypted:  {}\n", rsa.decrypt(&cipher));

    // ── Timing attack on a fresh 512-bit key ─────────────────────────────────
    println!("=============== Timing Attack ===============");
    let small = Rsa::generate(512);
    timing_attack(
        &small,
        /* n_samples  */ 1000,
        /* n_reps     */ 10000,
        /* n_iters    */ 5,
        /* known_bits */ 16,
        /* beam       */ 3,
    );
}
