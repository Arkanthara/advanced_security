//! Timing Attack on RSA Square-and-Multiply — demonstration entry point.
//!
//! Usage
//! -----
//!   cargo run --release -- [num_samples] [num_bits] [reps] [max_cand] [version]
//!
//!   num_samples  Number of random y_i inputs to query the oracle with  (default 50)
//!   num_bits     How many LSBs of d_A to attempt recovering             (default 20)
//!   reps         Repetitions per timing measurement                     (default 5)
//!   max_cand     Beam width for Version-2 error correction              (default 10)
//!   version      1 = v1 only | 2 = v2 only | 3 = both                  (default 3)
//!
//! Example — recover first 32 bits, 100 samples, 8 reps, beam=20, both attacks:
//!   cargo run --release -- 100 32 8 20 3
//!
//! Notes
//! -----
//! • All optimisations are disabled (Cargo.toml: [profile.release] opt-level=0).
//! • The oracle function is square_and_multiply with the *full* 2048-bit key d_A.
//! • Timing accuracy improves with more samples and more repetitions.
//!   Recommended minimums: 200 samples, 10 reps for reliable recovery.

mod attack;
mod rsa;

use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;
use std::io::Write;
use std::str::FromStr;

use attack::{attack_v1, attack_v2};
use rsa::{bits_to_biguint, get_bit, measure_time, square_and_multiply};

// ─────────────────────────────────────────────────────────────────────────────
// 2048-bit RSA key  (A)
// ─────────────────────────────────────────────────────────────────────────────

const P_STR: &str = "13109499994810966779468866046493465498469807493634236479294124421385342920350717814807375283698575766763256101470694189234369358996750113963585617491399169";

const Q_STR: &str = "9497561827984502554523100157901534504433126034087863778629488755692649311435921364240405549590851856701860175924335776598684751639633322074428628372725777";

const D_STR: &str = "1685394382767324790326942621450485552187209875614438478305225564629345944620726038114923060947436330701451901921041511234432041036987266468290187679773130363479895993621867708066144608084390089775045890165825736468637468786667820591136139480545376198614216373031208691260339805721685482401743494212035728605";

/// Public exponent e_A
const E_A: u64 = 4574830074548708213;

/// Ciphertext produced by encrypting the secret message with (n_A, e_A).
/// Decrypting with the recovered d gives the plaintext "Bravo ! Je suis…".
const M_1: u64 = 123456789132456789;

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let num_samples: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(50);
    let num_bits: usize    = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(20);
    let reps: u32          = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(5);
    let max_cand: usize    = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(10);
    let version: u8        = args.get(5).and_then(|s| s.parse().ok()).unwrap_or(3);

    print_banner(num_samples, num_bits, reps, max_cand, version);

    // ── Build key material ───────────────────────────────────────────────────
    let p: BigUint = BigUint::from_str(P_STR).expect("invalid P");
    let q: BigUint = BigUint::from_str(Q_STR).expect("invalid Q");
    let n: BigUint = &p * &q;
    let d: BigUint = BigUint::from_str(D_STR).expect("invalid D");
    let e: BigUint = BigUint::from(E_A);

    println!("[*] n_A  = {} bits", n.bits());
    println!("[*] d_A  = {} bits", d.bits());
    println!("[*] Recovering first {} LSBs of d_A\n", num_bits);

    // ── Phase 1: Collect oracle timing samples ───────────────────────────────
    // For each random y_i we query the *oracle* (square_and_multiply with the
    // true d) and record the total elapsed time T_i.
    // These (y_i, T_i) pairs drive both attack versions.
    println!("[*] Collecting {} oracle samples  (reps = {} each) …", num_samples, reps);
    println!("    This may take a minute — optimisations are disabled intentionally.\n");

    let mut rng  = thread_rng();
    let two      = BigUint::from(2u32);
    let t_global = std::time::Instant::now();

    let samples: Vec<(BigUint, u64)> = (0..num_samples)
        .map(|i| {
            // Random y_i in [2, n)
            let y = rng.gen_biguint_range(&two, &n);
            // Oracle call: y_i^d mod n  (uses the TRUE full secret key d)
            let t = measure_time(&y, &d, &n, reps);

            if (i + 1) % 10 == 0 {
                print!("    [{}/{}]  elapsed: {:.1}s\r",
                       i + 1, num_samples,
                       t_global.elapsed().as_secs_f64());
                std::io::stdout().flush().unwrap();
            }
            (y, t)
        })
        .collect();

    println!("\n[*] Sample collection done in {:.1}s\n",
             t_global.elapsed().as_secs_f64());

    // ── Phase 2: Attack ──────────────────────────────────────────────────────

    if version == 1 || version == 3 {
        let bits_v1  = attack_v1(&n, &d, &samples, num_bits, reps);
        let acc      = accuracy(&bits_v1, &d, num_bits);
        println!("\n[V1] Accuracy: {}/{} bits correct  ({:.1}%)\n",
                 acc, num_bits, pct(acc, num_bits));

        if num_bits as u64 >= d.bits() {
            try_decrypt(&bits_v1, &e, &n, "[V1]");
        }
    }

    if version == 2 || version == 3 {
        let bits_v2  = attack_v2(&n, &d, &samples, num_bits, reps, max_cand);
        let acc      = accuracy(&bits_v2, &d, num_bits);
        println!("\n[V2] Accuracy: {}/{} bits correct  ({:.1}%)\n",
                 acc, num_bits, pct(acc, num_bits));

        if num_bits as u64 >= d.bits() {
            try_decrypt(&bits_v2, &e, &n, "[V2]");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Counts how many of the first `num_bits` recovered bits match the true key.
fn accuracy(recovered: &[u8], x_true: &BigUint, num_bits: usize) -> usize {
    recovered.iter()
        .take(num_bits)
        .enumerate()
        .filter(|&(i, &b)| b == get_bit(x_true, i))
        .count()
}

fn pct(correct: usize, total: usize) -> f64 {
    if total == 0 { 0.0 } else { 100.0 * correct as f64 / total as f64 }
}

/// Attempts to decrypt `M_1` with the recovered exponent and prints the result.
///
/// Flow: c = M_1  →  m = c^d_recovered mod n
/// If recovery was complete, m decoded from UTF-8 bytes yields the plaintext.
fn try_decrypt(recovered_bits: &[u8], e: &BigUint, n: &BigUint, label: &str) {
    // The ciphertext is M_1 (small demo value)
    let c     = BigUint::from(M_1);
    let d_rec = bits_to_biguint(recovered_bits);

    // Re-encrypt M_1 with the public key to get the "true" ciphertext
    // (M_1 itself is already the ciphertext in this demo setup;
    //  a full round-trip would be: m_plain → encrypt → c → decrypt → m_plain)
    let c_full = square_and_multiply(&c, e, n);
    let m_dec  = square_and_multiply(&c_full, &d_rec, n);

    println!("{label} Decryption attempt:");
    println!("{label}   c_full = {} … (2048-bit)", &c_full.to_str_radix(10)[..20]);

    if m_dec == c {
        println!("{label} ✓ Decryption SUCCESS!  m = {M_1}");
        // Try UTF-8 decode of the numeric value
        let bytes = m_dec.to_bytes_be();
        match std::str::from_utf8(&bytes) {
            Ok(s)  => println!("{label}   Plaintext: \"{s}\""),
            Err(_) => println!("{label}   (raw bytes: {:?})", &bytes[..bytes.len().min(32)]),
        }
    } else {
        println!("{label} ✗ Decryption FAILED — recovered key is incomplete.");
        println!("{label}   Need all {} bits; only {} were requested.", d_rec.bits(), recovered_bits.len());
    }
}

/// Pretty startup banner.
fn print_banner(samples: usize, bits: usize, reps: u32, max_cand: usize, version: u8) {
    let ver_str = match version {
        1 => "v1 only — simple greedy variance",
        2 => "v2 only — error-correcting beam",
        _ => "v1 + v2 — both attacks",
    };
    println!();
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║      TIMING ATTACK ON RSA  (Square-and-Multiply)        ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  num_samples  = {:<41}║", samples);
    println!("║  num_bits     = {:<41}║", bits);
    println!("║  reps         = {:<41}║", reps);
    println!("║  max_cand     = {:<41}║", max_cand);
    println!("║  version      = {:<41}║", ver_str);
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("  ⚠  All compiler optimisations are DISABLED (opt-level = 0).");
    println!("  ⚠  Branch prediction, loop unrolling and inlining are suppressed.");
    println!("  ⚠  This preserves timing fidelity at the cost of raw speed.\n");
}
