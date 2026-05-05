/**
 * =============================================================================
 * RSA Timing Side-Channel Attack — Educational Implementation
 * =============================================================================
 *
 * OVERVIEW
 * --------
 * This program demonstrates Kocher's timing attack against RSA decryption.
 * The core insight: if a modular exponentiation routine takes measurably
 * different time depending on the bits of the secret exponent, an attacker
 * can recover those bits one by one by correlating timing measurements with
 * partial guesses of the exponent.
 *
 * STRUCTURE
 * ---------
 *   1. BigInt<L>          — fixed-width unsigned integer (L × 64-bit limbs)
 *   2. Arithmetic ops     — cmp, sub, mul_wide, mod, mul_mod, pow_mod
 *   3. RSA key generation — using GMP for primality testing
 *   4. Timing oracle      — measures decryption time on real ciphertexts
 *   5. Bit recovery       — beam-search over exponent bits using timing scores
 *
 * COMPILE
 * -------
 *   g++ -O2 -o attack rsa_timing_attack.cpp -lgmp -lgmpxx
 *   # To change key size: -DMOD_LIMBS=8 (default: 4 → 256-bit modulus)
 *
 * USAGE
 *   ./attack [num_ciphertexts] [reps_per_cipher] [beam_width]
 *   ./attack 64 8 4
 *
 * WARNING
 * -------
 *   This is a deliberately non-constant-time implementation, for educational
 *   purposes only. Real RSA libraries use blinding and constant-time code.
 * =============================================================================
 */

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <gmpxx.h>
#include <iostream>
#include <random>
#include <string>
#include <vector>

// =============================================================================
// Section 1 — Configuration
// =============================================================================

/**
 * MOD_LIMBS: number of 64-bit words in the RSA modulus n = p × q.
 * PRIME_LIMBS: number of words in each prime (half of MOD_LIMBS).
 *
 * Default: MOD_LIMBS = 4  →  256-bit modulus, 128-bit primes.
 * For 1024-bit RSA use -DMOD_LIMBS=16.
 */
#ifndef MOD_LIMBS
#define MOD_LIMBS 4
#endif
static_assert(MOD_LIMBS % 2 == 0, "MOD_LIMBS must be even so primes are exactly half the width");

constexpr std::size_t PRIME_LIMBS = MOD_LIMBS / 2;

// Convenience type aliases used throughout
using PrimeWord = BigInt<PRIME_LIMBS>;   // forward-declared; defined below
using ModWord   = BigInt<MOD_LIMBS>;

// =============================================================================
// Section 2 — BigInt<L>: a fixed-width, little-endian unsigned integer
// =============================================================================

/**
 * BigInt<L> stores an unsigned integer as L 64-bit limbs in *little-endian*
 * order: limbs[0] is the least-significant word, limbs[L-1] the most.
 *
 * The width is fixed at compile time; no heap allocation is ever performed.
 * Overflow simply wraps (limbs above index L-1 are lost), which is fine
 * because we always reduce modulo n after multiplication.
 */
template <std::size_t L>
struct BigInt {

    std::array<std::uint64_t, L> limbs{};  // zero-initialised by default

    // -------------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------------

    BigInt() = default;

    /** Construct from a small 64-bit value (higher limbs are zero). */
    explicit BigInt(std::uint64_t small_value) {
        limbs.fill(0);
        limbs[0] = small_value;
    }

    static BigInt zero() { return BigInt(0); }
    static BigInt one()  { return BigInt(1); }

    // -------------------------------------------------------------------------
    // Bit-level predicates and accessors
    // -------------------------------------------------------------------------

    bool is_zero() const {
        for (auto word : limbs)
            if (word != 0) return false;
        return true;
    }

    bool is_even() const { return (limbs[0] & 1ULL) == 0; }

    /** Index of the highest set bit + 1 (i.e. ceil(log2(x+1))). Returns 0 for zero. */
    std::size_t bit_length() const {
        for (std::size_t i = L; i-- > 0;)
            if (limbs[i] != 0)
                return i * 64 + (64 - __builtin_clzll(limbs[i]));
        return 0;
    }

    /** Read the i-th bit (0 = LSB). */
    bool bit(std::size_t bit_index) const {
        const std::size_t word = bit_index / 64;
        const std::size_t pos  = bit_index % 64;
        if (word >= L) return false;
        return (limbs[word] >> pos) & 1ULL;
    }

    /** Set or clear the i-th bit. */
    void set_bit(std::size_t bit_index, bool value) {
        const std::size_t word = bit_index / 64;
        const std::size_t pos  = bit_index % 64;
        if (word >= L) return;
        if (value) limbs[word] |=  (1ULL << pos);
        else       limbs[word] &= ~(1ULL << pos);
    }

    // -------------------------------------------------------------------------
    // Display helpers
    // -------------------------------------------------------------------------

    /** Return the binary representation (no leading zeros, at least "0"). */
    std::string to_binary_string() const {
        std::size_t len = bit_length();
        if (len == 0) return "0";
        std::string s;
        s.reserve(len);
        for (std::size_t i = len; i-- > 0;)
            s += bit(i) ? '1' : '0';
        return s;
    }
};

// =============================================================================
// Section 3 — Arithmetic on BigInt<L>
// =============================================================================

// ---- 3.1 Comparison ----

/**
 * Three-way comparison: returns -1, 0, or +1.
 * Scans from most-significant limb to least-significant.
 */
template <std::size_t L>
int compare(const BigInt<L>& a, const BigInt<L>& b) {
    for (std::size_t i = L; i-- > 0;) {
        if (a.limbs[i] < b.limbs[i]) return -1;
        if (a.limbs[i] > b.limbs[i]) return +1;
    }
    return 0;
}

template <std::size_t L>
bool operator>=(const BigInt<L>& a, const BigInt<L>& b) {
    return compare(a, b) >= 0;
}

// ---- 3.2 Subtraction (assumes a >= b, no underflow check) ----

/**
 * Returns a - b.  Caller must ensure a >= b to avoid wrapping.
 * Uses __int128 to detect borrow cleanly without UB.
 */
template <std::size_t L>
BigInt<L> subtract(const BigInt<L>& a, const BigInt<L>& b) {
    BigInt<L> result;
    std::uint64_t borrow = 0;

    for (std::size_t i = 0; i < L; ++i) {
        __int128 minuend    = (__int128)a.limbs[i];
        __int128 subtrahend = (__int128)b.limbs[i] + borrow;

        if (minuend >= subtrahend) {
            result.limbs[i] = (std::uint64_t)(minuend - subtrahend);
            borrow = 0;
        } else {
            // Borrow one "unit" (2^64) from the next limb
            result.limbs[i] = (std::uint64_t)(((__int128)1 << 64) + minuend - subtrahend);
            borrow = 1;
        }
    }

    return result;
}

// ---- 3.3 Wide multiplication: produces a 2L-limb result ----

/**
 * Schoolbook O(L²) multiplication.
 * Returns a × b as a BigInt<2L> so no information is lost before reduction.
 */
template <std::size_t L>
BigInt<2 * L> multiply_wide(const BigInt<L>& a, const BigInt<L>& b) {
    BigInt<2 * L> product;

    for (std::size_t i = 0; i < L; ++i) {
        __int128 carry = 0;
        for (std::size_t j = 0; j < L; ++j) {
            // Accumulate: product[i+j] += a[i]*b[j] + carry
            __int128 acc = (__int128)product.limbs[i + j]
                         + (__int128)a.limbs[i] * b.limbs[j]
                         + carry;
            product.limbs[i + j] = (std::uint64_t)acc;
            carry = acc >> 64;
        }
        product.limbs[i + L] += (std::uint64_t)carry;
    }

    return product;
}

// ---- 3.4 Reduction: compute x mod m (binary long division) ----

/**
 * Reduces a 2L-limb value x modulo an L-limb modulus m.
 *
 * Algorithm: binary long division — processes x one bit at a time from MSB,
 * left-shifting the partial remainder and subtracting m when >= m.
 *
 * This is simple but O(bits²) — fine for our key sizes.
 */
template <std::size_t L>
BigInt<L> reduce(const BigInt<2 * L>& x, const BigInt<L>& modulus) {
    BigInt<L> remainder;

    for (std::size_t bit_pos = x.bit_length(); bit_pos-- > 0;) {
        // Left-shift remainder by 1 bit
        for (int k = (int)L - 1; k >= 0; --k) {
            remainder.limbs[k] <<= 1;
            if (k > 0 && (remainder.limbs[k - 1] >> 63))
                remainder.limbs[k] |= 1;
        }

        // Bring in the next bit of x
        if (x.bit(bit_pos))
            remainder.limbs[0] |= 1;

        // Subtract modulus if remainder has grown too large
        if (remainder >= modulus)
            remainder = subtract(remainder, modulus);
    }

    return remainder;
}

// ---- 3.5 Modular multiplication and exponentiation ----

/** Computes (a × b) mod m. */
template <std::size_t L>
BigInt<L> mul_mod(const BigInt<L>& a, const BigInt<L>& b, const BigInt<L>& modulus) {
    return reduce<L>(multiply_wide(a, b), modulus);
}

/**
 * Computes base^exponent mod modulus using the square-and-multiply algorithm.
 *
 * Scans bits of the exponent from most-significant to least-significant.
 * For each bit:
 *   - Always square the running result.
 *   - Additionally multiply by base if the current bit is 1.
 *
 * IMPORTANT: this is NOT constant-time — the multiply step only happens on
 * set bits, making the execution time dependent on the Hamming weight and
 * bit pattern of `exponent`.  That is exactly the vulnerability we exploit.
 */
template <std::size_t L>
BigInt<L> pow_mod(BigInt<L> base, const BigInt<L>& exponent, const BigInt<L>& modulus) {
    BigInt<L> result = BigInt<L>::one();

    for (std::size_t bit_pos = exponent.bit_length(); bit_pos-- > 0;) {
        result = mul_mod(result, result, modulus);          // always square
        if (exponent.bit(bit_pos))
            result = mul_mod(result, base, modulus);        // multiply if bit is set
    }

    return result;
}

// =============================================================================
// Section 4 — RSA Key Generation (using GMP for primality)
// =============================================================================

/** Bundles all RSA key material together. */
struct RSAKeyPair {
    ModWord   n;    ///< Public modulus   n = p × q
    ModWord   e;    ///< Public exponent  (65537)
    ModWord   d;    ///< Private exponent d = e^{-1} mod φ(n)
    ModWord   phi;  ///< Euler totient    φ(n) = (p-1)(q-1)
    PrimeWord p;    ///< First prime factor
    PrimeWord q;    ///< Second prime factor
};

// ---- GMP ↔ BigInt conversion helpers ----

/** Import a GMP integer into our BigInt representation (little-endian limbs). */
template <std::size_t L>
BigInt<L> from_gmp(const mpz_class& z) {
    BigInt<L> result;
    std::vector<std::uint64_t> words(L, 0);
    std::size_t word_count = 0;
    mpz_export(words.data(), &word_count, /*order=*/-1, /*size=*/8,
               /*endian=*/0, /*nails=*/0, z.get_mpz_t());
    for (std::size_t i = 0; i < word_count; ++i)
        result.limbs[i] = words[i];
    return result;
}

/** Export our BigInt to a GMP integer. */
template <std::size_t L>
mpz_class to_gmp(const BigInt<L>& x) {
    mpz_class z;
    mpz_import(z.get_mpz_t(), L, /*order=*/-1, /*size=*/8,
               /*endian=*/0, /*nails=*/0, x.limbs.data());
    return z;
}

/**
 * Generate a random prime with exactly PRIME_LIMBS × 64 bits.
 * Uses GMP's mpz_nextprime for primality testing.
 */
PrimeWord generate_prime(gmp_randstate_t rng_state) {
    mpz_class candidate;
    while (true) {
        // Random odd PRIME_LIMBS*64-bit number with MSB set
        mpz_urandomb(candidate.get_mpz_t(), rng_state, PRIME_LIMBS * 64);
        mpz_setbit(candidate.get_mpz_t(), PRIME_LIMBS * 64 - 1);  // ensure full bit-width
        mpz_setbit(candidate.get_mpz_t(), 0);                       // ensure odd

        mpz_nextprime(candidate.get_mpz_t(), candidate.get_mpz_t());

        // Accept only if the prime fits exactly in PRIME_LIMBS*64 bits
        if (mpz_sizeinbase(candidate.get_mpz_t(), 2) == PRIME_LIMBS * 64)
            break;
    }
    return from_gmp<PRIME_LIMBS>(candidate);
}

/**
 * Compute the modular inverse of `a` modulo `m` using GMP's mpz_invert.
 * Returns x such that a × x ≡ 1 (mod m).
 */
ModWord modular_inverse(const ModWord& a, const ModWord& m) {
    mpz_class gmp_a = to_gmp(a);
    mpz_class gmp_m = to_gmp(m);
    mpz_class inverse;
    mpz_invert(inverse.get_mpz_t(), gmp_a.get_mpz_t(), gmp_m.get_mpz_t());
    return from_gmp<MOD_LIMBS>(inverse);
}

/**
 * Generate a fresh RSA key pair.
 *
 *   p, q  ← random primes of PRIME_LIMBS*64 bits
 *   n     = p × q
 *   φ(n)  = (p−1)(q−1)
 *   e     = 65537   (standard public exponent)
 *   d     = e^{-1} mod φ(n)
 */
RSAKeyPair generate_rsa_keypair() {
    gmp_randstate_t rng_state;
    gmp_randinit_default(rng_state);
    gmp_randseed_ui(rng_state, time(nullptr));

    // Generate two distinct primes
    PrimeWord p = generate_prime(rng_state);
    PrimeWord q = generate_prime(rng_state);
    while (compare(p, q) == 0)
        q = generate_prime(rng_state);

    // n = p × q  (result fits exactly in MOD_LIMBS limbs since each factor is PRIME_LIMBS)
    auto n_wide = multiply_wide(p, q);
    ModWord n;
    for (std::size_t i = 0; i < MOD_LIMBS; ++i)
        n.limbs[i] = n_wide.limbs[i];

    // φ(n) = (p−1)(q−1)
    auto phi_wide = multiply_wide(subtract(p, PrimeWord(1)),
                                  subtract(q, PrimeWord(1)));
    ModWord phi;
    for (std::size_t i = 0; i < MOD_LIMBS; ++i)
        phi.limbs[i] = phi_wide.limbs[i];

    ModWord e(65537);
    ModWord d = modular_inverse(e, phi);

    gmp_randclear(rng_state);
    return {n, e, d, phi, p, q};
}

// =============================================================================
// Section 5 — Timing Oracle
// =============================================================================

/**
 * Measure the average time (in nanoseconds) to decrypt ciphertext `c`
 * using private exponent `d` and modulus `n`.
 *
 * We repeat `num_repetitions` times and return the mean, to reduce noise.
 */
template <std::size_t L>
double measure_decryption_time(const BigInt<L>& ciphertext,
                               const BigInt<L>& private_exponent,
                               const BigInt<L>& modulus,
                               int num_repetitions)
{
    auto start = std::chrono::high_resolution_clock::now();
    for (int rep = 0; rep < num_repetitions; ++rep)
        pow_mod(ciphertext, private_exponent, modulus);
    auto end   = std::chrono::high_resolution_clock::now();

    return std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count()
           / double(num_repetitions);
}

// =============================================================================
// Section 6 — Timing Attack: recovering the private exponent bit by bit
// =============================================================================

/**
 * Timing Score for a Candidate Exponent Guess
 * --------------------------------------------
 * Given a partial guess `guess` of the private exponent (bits already
 * recovered + the current bit being tested), we compute a *score* that
 * measures how well `guess` correlates with the observed timing data.
 *
 * The idea:
 *   - For each ciphertext cᵢ we have a measured decryption time tᵢ.
 *   - We also time pow_mod(cᵢ, guess, n) ourselves.
 *   - The residual rᵢ = tᵢ − (time with guess) captures timing variance
 *     NOT explained by the known bits in `guess`.
 *   - We return the variance of these residuals: a correct guess for the
 *     current bit will make rᵢ smaller on average, reducing the variance.
 *
 * Lower score = better guess.
 */
template <std::size_t L>
double timing_score(const BigInt<L>&              candidate_exponent,
                    const std::vector<BigInt<L>>& ciphertexts,
                    const std::vector<double>&    observed_times,
                    const BigInt<L>&              modulus)
{
    double sum    = 0.0;
    double sum_sq = 0.0;

    for (std::size_t i = 0; i < ciphertexts.size(); ++i) {
        auto   t0       = std::chrono::high_resolution_clock::now();
        pow_mod(ciphertexts[i], candidate_exponent, modulus);
        auto   t1       = std::chrono::high_resolution_clock::now();
        double elapsed  = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();

        double residual = observed_times[i] - elapsed;
        sum    += residual;
        sum_sq += residual * residual;
    }

    double mean     = sum / (double)ciphertexts.size();
    double variance = sum_sq / (double)ciphertexts.size() - mean * mean;
    return variance;  // lower is better
}

/**
 * Beam Search Over Exponent Bits
 * -------------------------------
 * We recover the private exponent d bit by bit, from most-significant to
 * least-significant, using a beam search of width `beam_width`.
 *
 * At each step we extend every surviving candidate by trying 0 and 1 for the
 * next bit, score all extensions, and keep only the `beam_width` best ones.
 *
 * This is essentially Kocher's 1996 timing attack.
 */
ModWord recover_private_exponent(const std::vector<ModWord>& ciphertexts,
                                 const std::vector<double>&  observed_times,
                                 const RSAKeyPair&           key,           // used for n and ground truth
                                 std::size_t                 beam_width)
{
    const std::size_t num_bits = key.d.bit_length();

    // The MSB of d is always 1 — start beam there
    std::vector<ModWord> beam(1);
    beam[0].set_bit(num_bits - 1, 1);

    // Recover bits from (MSB-1) down to 0
    for (std::size_t bit_index = num_bits - 1; bit_index-- > 0;) {

        // Build all extensions of the current beam
        std::vector<std::pair<ModWord, double>> candidates;
        candidates.reserve(beam.size() * 2);

        for (const auto& current : beam) {
            // Try setting the bit to 0
            ModWord with_zero = current;
            with_zero.set_bit(bit_index, 0);

            // Try setting the bit to 1
            ModWord with_one = current;
            with_one.set_bit(bit_index, 1);

            candidates.emplace_back(with_zero, timing_score(with_zero, ciphertexts, observed_times, key.n));
            candidates.emplace_back(with_one,  timing_score(with_one,  ciphertexts, observed_times, key.n));
        }

        // Keep the best `beam_width` candidates (lowest score = better fit)
        std::sort(candidates.begin(), candidates.end(),
                  [](const auto& a, const auto& b) { return a.second < b.second; });

        beam.clear();
        for (std::size_t i = 0; i < std::min(beam_width, candidates.size()); ++i)
            beam.push_back(candidates[i].first);

        // Progress report
        bool guessed_bit = beam[0].bit(bit_index);
        bool true_bit    = key.d.bit(bit_index);
        bool correct     = (guessed_bit == true_bit);

        std::cout << "  bit " << std::setw(4) << bit_index
                  << ": guessed=" << guessed_bit
                  << "  true=" << true_bit
                  << "  score=" << std::scientific << std::setprecision(3) << candidates[0].second
                  << "  " << (correct ? "✓" : "✗")
                  << "\n";
    }

    return beam[0];  // best surviving candidate
}

// =============================================================================
// Section 7 — Main
// =============================================================================

int main(int argc, char** argv) {

    // ---- Parse command-line arguments ----
    const std::size_t num_ciphertexts     = (argc > 1) ? std::stoull(argv[1]) : 32;
    const int         reps_per_ciphertext = (argc > 2) ? std::stoi(argv[2])   : 4;
    const std::size_t beam_width          = (argc > 3) ? std::stoull(argv[3]) : 4;

    std::cout << "=== RSA Timing Attack Demo ===\n";
    std::cout << "  Modulus size  : " << MOD_LIMBS * 64 << " bits\n";
    std::cout << "  Ciphertexts   : " << num_ciphertexts     << "\n";
    std::cout << "  Repetitions   : " << reps_per_ciphertext << " per ciphertext\n";
    std::cout << "  Beam width    : " << beam_width          << "\n\n";

    // ---- Step 1: Generate an RSA key pair (victim's secret key) ----
    std::cout << "[1] Generating RSA key pair...\n";
    const RSAKeyPair key = generate_rsa_keypair();
    std::cout << "    n = " << key.n.to_binary_string() << "\n";
    std::cout << "    d = " << key.d.to_binary_string() << "  (SECRET — shown for verification)\n\n";

    // ---- Step 2: Collect (ciphertext, decryption time) pairs ----
    std::cout << "[2] Collecting timing samples...\n";
    std::vector<ModWord> ciphertexts;
    std::vector<double>  observed_times;
    ciphertexts.reserve(num_ciphertexts);
    observed_times.reserve(num_ciphertexts);

    std::mt19937_64 rng(/*seed=*/42);

    for (std::size_t i = 0; i < num_ciphertexts; ++i) {
        // Build a random plaintext and encrypt it: c = m^e mod n
        ModWord plaintext;
        for (auto& word : plaintext.limbs) word = rng();

        ModWord ciphertext = pow_mod(plaintext, key.e, key.n);
        ciphertexts.push_back(ciphertext);

        // Time how long the victim takes to decrypt c
        double t = measure_decryption_time(ciphertext, key.d, key.n, reps_per_ciphertext);
        observed_times.push_back(t);

        std::cout << "    sample " << i + 1 << "/" << num_ciphertexts
                  << "  (" << t << " ns)\r" << std::flush;
    }
    std::cout << "\n\n";

    // ---- Step 3: Run the timing attack ----
    std::cout << "[3] Running bit-by-bit timing attack...\n";
    ModWord recovered_d = recover_private_exponent(ciphertexts, observed_times, key, beam_width);

    // ---- Step 4: Report results ----
    std::cout << "\n[4] Results\n";
    std::cout << "    Recovered d : " << recovered_d.to_binary_string() << "\n";
    std::cout << "    True d      : " << key.d.to_binary_string()       << "\n";

    bool success = (compare(recovered_d, key.d) == 0);
    std::cout << (success ? "\n  ✓ Full key recovered!\n" : "\n  ✗ Key recovery failed — try more ciphertexts or repetitions.\n");

    return success ? 0 : 1;
}
