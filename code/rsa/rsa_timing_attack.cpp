/**
 * Kocher's Timing Attack on RSA (1996) — C++ implementation
 * ==========================================================
 *
 * WHY THIS WORKS
 * --------------
 * Square-and-multiply modular exponentiation processes the secret exponent
 * one bit at a time (LSB first):
 *
 *     while x > 0:
 *         if bit(x, 0) == 1:          ← extra multiply when bit = 1  (slower)
 *             s = s * y  mod n
 *         y = y * y  mod n            ← always done
 *         x >>= 1
 *
 * Each "1" bit costs one extra modular multiplication.  The cumulative timing
 * difference leaks across many ciphertexts via a simple variance test.
 *
 * WHY C++ INSTEAD OF PYTHON
 * -------------------------
 * Python's big-integer runtime, GIL, garbage collector and JIT-like optimisations
 * swamp the per-multiplication timing signal (~microseconds) with milliseconds of
 * noise.  C++ with GMP performs raw GMP multiplications with nanosecond precision
 * and no hidden overhead, making the signal reliably observable.
 *
 * STATISTICAL STRATEGY (Kocher 1996 §4)
 * --------------------------------------
 * Collect m ciphertexts y_i with their server decryption times T_i.
 * To guess bit b (knowing bits 0..b-1 = prefix):
 *
 *   1. Form hypothesis h = prefix | (guess << b)  for guess in {0, 1}
 *   2. Locally simulate the first (b+1) iterations → estimate t(y_i, h)
 *   3. Compute residuals  T'_i = T_i – t(y_i, h)
 *      • Correct guess  → residuals have LOW  variance (partial time explained)
 *      • Wrong guess    → residuals have HIGH variance (artificial noise added)
 *   4. Pick the hypothesis with minimum variance.
 *
 * TWO ATTACK VARIANTS
 * -------------------
 * V1 – Greedy  : commit to the best bit at each step (fast, may propagate errors)
 * V2 – Beam    : keep top-k candidates (self-correcting, slower)
 *
 * BUILD
 * -----
 *   g++ -O0 -o rsa_timing_attack rsa_timing_attack.cpp -lgmp -lgmpxx
 *
 * -O0 is critical: higher optimisation levels let the compiler cache GMP
 * intermediate results and eliminate the timing signal.
 */

#include <gmpxx.h>          // arbitrary-precision integers (GMP C++ wrapper)
#include <chrono>
#include <vector>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <iostream>
#include <cstdio>
#include <stdexcept>

// ─── Convenience aliases ─────────────────────────────────────────────────────

using Clock = std::chrono::high_resolution_clock;
using ns    = std::chrono::nanoseconds;
using mpz   = mpz_class;

// ─── Timing helper ────────────────────────────────────────────────────────────

static inline long long now_ns() {
    return std::chrono::duration_cast<ns>(Clock::now().time_since_epoch()).count();
}

// ─────────────────────────────────────────────────────────────────────────────
//  Big-integer helpers
// ─────────────────────────────────────────────────────────────────────────────

/** Uniform random mpz in [lo, hi]. */
static mpz rand_range(const mpz& lo, const mpz& hi, gmp_randstate_t rng) {
    mpz range = hi - lo + 1;
    mpz r;
    mpz_urandomm(r.get_mpz_t(), rng, range.get_mpz_t());
    return lo + r;
}

/** Modular inverse of a mod m (via GMP, which uses extended Euclidean). */
static mpz mod_inverse(const mpz& a, const mpz& m) {
    mpz inv;
    if (!mpz_invert(inv.get_mpz_t(), a.get_mpz_t(), m.get_mpz_t()))
        throw std::runtime_error("No modular inverse — gcd(a,m) != 1");
    return inv;
}

/** Generate a probable prime of exactly `bits` bits. */
static mpz random_prime(int bits, gmp_randstate_t rng) {
    mpz lo, hi;
    mpz_ui_pow_ui(lo.get_mpz_t(), 2, bits - 1);
    mpz_ui_pow_ui(hi.get_mpz_t(), 2, bits); hi -= 1;
    for (;;) {
        mpz c = rand_range(lo, hi, rng);
        if (mpz_probab_prime_p(c.get_mpz_t(), 20) > 0)
            return c;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Vulnerable square-and-multiply modular exponentiation
//
//  This is the textbook implementation.  The conditional multiply when a bit
//  equals 1 is the timing oracle the attacker exploits.
// ─────────────────────────────────────────────────────────────────────────────

static mpz modpow(const mpz& base, const mpz& exp, const mpz& n) {
    mpz s = 1;
    mpz y = base % n;
    mpz x = exp;
    while (x > 0) {
        if (mpz_odd_p(x.get_mpz_t()))      // bit = 1 → extra multiply (leaks timing)
            s = s * y % n;
        y = y * y % n;                      // always square
        x >>= 1;
    }
    return s;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Partial modpow simulation (attacker side)
//
//  Reproduce the first `n_bits` loop iterations of modpow(base, prefix, n)
//  and return the wall-clock time in nanoseconds.
//
//  This gives t(y_i, hypothesis) — the portion of the server's time that
//  corresponds to the guessed prefix bits.
// ─────────────────────────────────────────────────────────────────────────────

static long long partial_modpow_ns(const mpz& base, const mpz& prefix,
                                    int n_bits, const mpz& n) {
    mpz s = 1;
    mpz y = base % n;
    mpz x = prefix;
    long long t0 = now_ns();
    for (int i = 0; i < n_bits; ++i) {
        if (mpz_odd_p(x.get_mpz_t()))
            s = s * y % n;
        y = y * y % n;
        x >>= 1;
    }
    return now_ns() - t0;
}

// ─────────────────────────────────────────────────────────────────────────────
//  RSA key pair and Server
// ─────────────────────────────────────────────────────────────────────────────

struct RSAKey { mpz n, e, d; };

static RSAKey generate_keypair(int key_bits, gmp_randstate_t rng) {
    int half = key_bits / 2;
    mpz p = random_prime(half, rng);
    mpz q = random_prime(half, rng);
    mpz n   = p * q;
    mpz phi = (p - 1) * (q - 1);
    mpz e   = 65537;                    // standard public exponent
    mpz d   = mod_inverse(e, phi);
    return {n, e, d};
}

/**
 * Server: holds the RSA private key and answers decrypt queries.
 * The only observable output is the decryption time.
 */
struct Server {
    mpz n, e;               // public
    mpz d;                  // secret (only visible here for verification)

    /**
     * Decrypt `cipher` using d and return the median elapsed time (ns)
     * over `repeat` runs.  The median reduces OS scheduling outliers.
     */
    long long timed_decrypt(const mpz& cipher, int repeat = 7) const {
        std::vector<long long> times(repeat);
        for (int i = 0; i < repeat; ++i) {
            long long t0 = now_ns();
            modpow(cipher, d, n);
            times[i] = now_ns() - t0;
        }
        std::sort(times.begin(), times.end());
        return times[repeat / 2];           // median
    }
};

// ─────────────────────────────────────────────────────────────────────────────
//  Timing sample
// ─────────────────────────────────────────────────────────────────────────────

struct Sample {
    mpz       cipher;       // the ciphertext sent to the server
    long long time_ns;      // server's observed decryption time
};

/**
 * Send `count` random ciphertexts to the server and record timing.
 * The attacker encrypts random messages to produce valid ciphertexts.
 */
static std::vector<Sample> collect_samples(const Server& srv, int count,
                                            int repeat, gmp_randstate_t rng) {
    std::vector<Sample> samples;
    samples.reserve(count);
    for (int i = 0; i < count; ++i) {
        mpz y = rand_range(2, srv.n - 1, rng);
        mpz cipher;
        mpz_powm(cipher.get_mpz_t(), y.get_mpz_t(), srv.e.get_mpz_t(), srv.n.get_mpz_t());
        long long t = srv.timed_decrypt(cipher, repeat);
        samples.push_back({cipher, t});
        if ((i + 1) % 50 == 0)
            std::printf("  collected %d / %d samples\n", i + 1, count);
    }
    return samples;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Core statistical tool — corrected variance
//
//  Compute Var( T_i - t(y_i, hypothesis) ).
//
//  A correct hypothesis explains part of the server's timing, shrinking the
//  variance of the residuals.  A wrong hypothesis introduces noise, inflating
//  the variance.
// ─────────────────────────────────────────────────────────────────────────────

static double corrected_variance(const std::vector<Sample>& samples,
                                  const mpz& hypothesis, int n_bits,
                                  const mpz& n, int sim_repeat = 3) {
    std::vector<double> residuals;
    residuals.reserve(samples.size());

    for (const auto& s : samples) {
        // Average the local simulation over sim_repeat runs to reduce noise
        long long sum = 0;
        for (int r = 0; r < sim_repeat; ++r)
            sum += partial_modpow_ns(s.cipher, hypothesis, n_bits, n);
        double partial  = static_cast<double>(sum) / sim_repeat;
        residuals.push_back(static_cast<double>(s.time_ns) - partial);
    }

    double mean = 0.0;
    for (double r : residuals) mean += r;
    mean /= residuals.size();

    double var = 0.0;
    for (double r : residuals) var += (r - mean) * (r - mean);
    return var / residuals.size();
}

// ─────────────────────────────────────────────────────────────────────────────
//  Attack V1 — Simple Greedy
//
//  Recover `n_bits` of the secret exponent bit by bit.
//  At step b: test bit=0 and bit=1, commit to whichever gives lower variance.
// ─────────────────────────────────────────────────────────────────────────────

static mpz attack_v1(const Server& srv, const std::vector<Sample>& samples,
                      int n_bits, int sim_repeat = 3) {
    std::printf("\n══ V1 – Greedy attack (%d bits) ══\n", n_bits);
    std::printf("  %3s  %5s  %12s  %12s  %s\n",
                "Bit", "Guess", "Var(bit=0)", "Var(bit=1)", "Correct?");

    mpz recovered = 0;
    int n_correct  = 0;

    for (int b = 0; b < n_bits; ++b) {
        double var[2];
        for (int bit : {0, 1}) {
            mpz hyp = recovered | (mpz(bit) << b);
            var[bit] = corrected_variance(samples, hyp, b + 1, srv.n, sim_repeat);
        }

        int best   = (var[0] < var[1]) ? 0 : 1;
        recovered |= (mpz(best) << b);

        // Evaluate against the true secret (for demo purposes only)
        int actual = (int)mpz_tstbit(srv.d.get_mpz_t(), b);
        bool ok    = (best == actual);
        if (ok) ++n_correct;

        std::printf("  %3d  %5d  %12.3e  %12.3e  %s\n",
                    b, best, var[0], var[1], ok ? "✓" : "✗");
    }

    std::printf("  Accuracy: %d / %d  (%.0f%%)\n",
                n_correct, n_bits, 100.0 * n_correct / n_bits);
    return recovered;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Attack V2 — Beam Search
//
//  Keep the `beam_width` best candidate prefixes at each bit step.
//  A wrong bit produces higher variance and will be pruned; the correct branch
//  stays at the top.  This lets the attack recover from early errors.
// ─────────────────────────────────────────────────────────────────────────────

static mpz attack_v2(const Server& srv, const std::vector<Sample>& samples,
                      int n_bits, int beam_width = 8, int sim_repeat = 3) {
    std::printf("\n══ V2 – Beam search (%d bits, beam=%d) ══\n", n_bits, beam_width);

    using Candidate = std::pair<double, mpz>; // (variance, prefix)
    std::vector<Candidate> beam = {{0.0, mpz(0)}};

    for (int b = 0; b < n_bits; ++b) {
        std::vector<Candidate> next;
        next.reserve(beam.size() * 2);

        for (auto& [_, prefix] : beam) {
            for (int bit : {0, 1}) {
                mpz hyp = prefix | (mpz(bit) << b);
                double v = corrected_variance(samples, hyp, b + 1, srv.n, sim_repeat);
                next.push_back({v, hyp});
            }
        }

        // Keep the beam_width candidates with the lowest variance
        std::sort(next.begin(), next.end(),
                  [](const Candidate& a, const Candidate& b) { return a.first < b.first; });
        if ((int)next.size() > beam_width) next.resize(beam_width);
        beam = std::move(next);

        // Display the top candidates at this bit position
        std::printf("  Bit %2d:", b);
        for (int i = 0; i < std::min(3, (int)beam.size()); ++i)
            gmp_printf("  0x%Zx(%.1e)", beam[i].second.get_mpz_t(), beam[i].first);
        std::printf("\n");
    }

    mpz best = beam[0].second;

    // Evaluate bit-by-bit accuracy
    int n_correct = 0;
    for (int b = 0; b < n_bits; ++b)
        if ((int)mpz_tstbit(best.get_mpz_t(), b) ==
            (int)mpz_tstbit(srv.d.get_mpz_t(), b))
            ++n_correct;

    std::printf("  Accuracy: %d / %d  (%.0f%%)\n",
                n_correct, n_bits, 100.0 * n_correct / n_bits);
    return best;
}

// ─────────────────────────────────────────────────────────────────────────────
//  MAIN
// ─────────────────────────────────────────────────────────────────────────────

int main() {
    // ── Experiment parameters ────────────────────────────────────────────────
    constexpr int KEY_BITS   = 512;  // RSA modulus size (toy; real RSA uses ≥2048)
    constexpr int N_BITS     = 16;   // number of secret-exponent bits to recover
    constexpr int N_SAMPLES  = 20000;  // timing ciphertexts to collect
    constexpr int SRV_REPEAT = 7;    // server-side median-filter window
    constexpr int SIM_REPEAT = 3;    // attacker-side simulation repeats
    constexpr int BEAM_WIDTH = 8;    // V2 beam width

    // ── Seeded RNG ───────────────────────────────────────────────────────────
    gmp_randstate_t rng;
    gmp_randinit_default(rng);
    gmp_randseed_ui(rng, 42);

    // ── Key generation ───────────────────────────────────────────────────────
    std::printf("Generating %d-bit RSA key pair…\n", KEY_BITS);
    RSAKey key = generate_keypair(KEY_BITS, rng);
    Server srv{key.n, key.e, key.d};
    std::printf("  n = %zu bits\n", mpz_sizeinbase(srv.n.get_mpz_t(), 2));
    std::printf("  d = %zu bits  (first %d bits secret)\n\n",
                mpz_sizeinbase(srv.d.get_mpz_t(), 2), N_BITS);

    // ── Collect timing samples (single pass, reused by both attacks) ─────────
    std::printf("Collecting %d timing samples (median of %d runs each)…\n",
                N_SAMPLES, SRV_REPEAT);
    auto samples = collect_samples(srv, N_SAMPLES, SRV_REPEAT, rng);

    // ── Run both attack variants ─────────────────────────────────────────────
    mpz r1 = attack_v1(srv, samples, N_BITS, SIM_REPEAT);
    mpz r2 = attack_v2(srv, samples, N_BITS, BEAM_WIDTH, SIM_REPEAT);

    // ── Summary ──────────────────────────────────────────────────────────────
    mpz mask     = (mpz(1) << N_BITS) - 1;
    mpz expected = srv.d & mask;

    std::printf("\n══════════════════════════════════════\n");
    std::printf("  FINAL SUMMARY  (%d LSBs of secret d)\n", N_BITS);
    gmp_printf("  Target : 0x%Zx\n", expected.get_mpz_t());
    gmp_printf("  V1     : 0x%Zx  %s\n", r1.get_mpz_t(), r1 == expected ? "✓" : "✗");
    gmp_printf("  V2     : 0x%Zx  %s\n", r2.get_mpz_t(), r2 == expected ? "✓" : "✗");
    std::printf("══════════════════════════════════════\n");

    gmp_randclear(rng);
    return 0;
}
