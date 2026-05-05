
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <gmpxx.h>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

// -----------------------------------------------------------------------------
// Build:
//   g++ -O2 -std=c++17 minimal_rsa_timing_attack.cpp -lgmpxx -lgmp
//
// Size:
//   MOD_LIMBS is the number of 64-bit limbs used for the RSA modulus.
//   2  -> 128-bit modulus
//   8  -> 512-bit modulus
//   32 -> 2048-bit modulus
//
// GMP is used only for prime generation. All RSA arithmetic below is hand-made.
// -----------------------------------------------------------------------------

#ifndef MOD_LIMBS
#define MOD_LIMBS 4  // default: 256-bit modulus for a fast demo
#endif

static_assert(MOD_LIMBS % 2 == 0, "MOD_LIMBS must be even.");
constexpr std::size_t PRIME_LIMBS = MOD_LIMBS / 2;

// -----------------------------------------------------------------------------
// Fixed-size unsigned big integer using 64-bit limbs.
// -----------------------------------------------------------------------------
template <std::size_t L>
struct BigInt {
    std::array<std::uint64_t, L> limbs{};

    BigInt() = default;
    explicit BigInt(std::uint64_t v) {
        limbs.fill(0);
        limbs[0] = v;
    }

    static BigInt zero() { return BigInt(0); }
    static BigInt one() { return BigInt(1); }

    bool is_zero() const {
        for (auto w : limbs) if (w != 0) return false;
        return true;
    }

    bool is_even() const { return (limbs[0] & 1ULL) == 0; }
    bool is_odd()  const { return !is_even(); }

    std::size_t bit_length() const {
        for (std::size_t i = L; i-- > 0;) {
            if (limbs[i] != 0) {
                return i * 64 + (64U - static_cast<unsigned>(__builtin_clzll(limbs[i])));
            }
        }
        return 0;
    }

    bool bit(std::size_t idx) const {
        std::size_t limb = idx / 64;
        if (limb >= L) return false;
        return (limbs[limb] >> (idx % 64)) & 1ULL;
    }

    void set_bit(std::size_t idx, bool value) {
        std::size_t limb = idx / 64;
        if (limb >= L) return;
        std::uint64_t mask = 1ULL << (idx % 64);
        if (value) limbs[limb] |= mask;
        else limbs[limb] &= ~mask;
    }

    void shl1() {
        std::uint64_t carry = 0;
        for (std::size_t i = 0; i < L; ++i) {
            std::uint64_t next = limbs[i] >> 63;
            limbs[i] = (limbs[i] << 1) | carry;
            carry = next;
        }
    }

    void shr1() {
        std::uint64_t carry = 0;
        for (std::size_t i = L; i-- > 0;) {
            std::uint64_t next = (limbs[i] & 1ULL) << 63;
            limbs[i] = (limbs[i] >> 1) | carry;
            carry = next;
        }
    }

    std::string to_hex() const {
        std::ostringstream oss;
        oss << std::hex;
        bool started = false;
        for (std::size_t i = L; i-- > 0;) {
            if (!started) {
                if (limbs[i] == 0) continue;
                oss << limbs[i];
                started = true;
            } else {
                oss << std::setw(16) << std::setfill('0') << limbs[i];
            }
        }
        return started ? oss.str() : "0";
    }
};

// -----------------------------------------------------------------------------
// Basic comparison / arithmetic.
// -----------------------------------------------------------------------------
template <std::size_t L>
int cmp(const BigInt<L>& a, const BigInt<L>& b) {
    for (std::size_t i = L; i-- > 0;) {
        if (a.limbs[i] < b.limbs[i]) return -1;
        if (a.limbs[i] > b.limbs[i]) return 1;
    }
    return 0;
}

template <std::size_t L>
bool operator==(const BigInt<L>& a, const BigInt<L>& b) { return cmp(a, b) == 0; }

template <std::size_t L>
bool operator!=(const BigInt<L>& a, const BigInt<L>& b) { return !(a == b); }

template <std::size_t L>
bool operator>=(const BigInt<L>& a, const BigInt<L>& b) { return cmp(a, b) >= 0; }

template <std::size_t L>
bool operator<(const BigInt<L>& a, const BigInt<L>& b) { return cmp(a, b) < 0; }

template <std::size_t L>
BigInt<L> add(const BigInt<L>& a, const BigInt<L>& b) {
    BigInt<L> r;
    std::uint64_t carry = 0;
    for (std::size_t i = 0; i < L; ++i) {
        unsigned __int128 s = static_cast<unsigned __int128>(a.limbs[i]) + b.limbs[i] + carry;
        r.limbs[i] = static_cast<std::uint64_t>(s);
        carry = static_cast<std::uint64_t>(s >> 64);
    }
    return r;
}

template <std::size_t L>
BigInt<L> sub(const BigInt<L>& a, const BigInt<L>& b) {
    // Assumes a >= b.
    BigInt<L> r;
    std::uint64_t borrow = 0;
    for (std::size_t i = 0; i < L; ++i) {
        unsigned __int128 ai = a.limbs[i];
        unsigned __int128 bi = static_cast<unsigned __int128>(b.limbs[i]) + borrow;
        if (ai >= bi) {
            r.limbs[i] = static_cast<std::uint64_t>(ai - bi);
            borrow = 0;
        } else {
            r.limbs[i] = static_cast<std::uint64_t>((static_cast<unsigned __int128>(1) << 64) + ai - bi);
            borrow = 1;
        }
    }
    return r;
}

template <std::size_t L>
BigInt<L> add_small(const BigInt<L>& a, std::uint64_t v) {
    BigInt<L> r = a;
    unsigned __int128 s = static_cast<unsigned __int128>(r.limbs[0]) + v;
    r.limbs[0] = static_cast<std::uint64_t>(s);
    std::uint64_t carry = static_cast<std::uint64_t>(s >> 64);
    for (std::size_t i = 1; i < L && carry; ++i) {
        unsigned __int128 t = static_cast<unsigned __int128>(r.limbs[i]) + carry;
        r.limbs[i] = static_cast<std::uint64_t>(t);
        carry = static_cast<std::uint64_t>(t >> 64);
    }
    return r;
}

// -----------------------------------------------------------------------------
// Schoolbook multiplication.
// -----------------------------------------------------------------------------
template <std::size_t L>
BigInt<2 * L> mul_wide(const BigInt<L>& a, const BigInt<L>& b) {
    BigInt<2 * L> r;
    for (std::size_t i = 0; i < L; ++i) {
        unsigned __int128 carry = 0;
        for (std::size_t j = 0; j < L; ++j) {
            unsigned __int128 cur = static_cast<unsigned __int128>(r.limbs[i + j]) +
                                    static_cast<unsigned __int128>(a.limbs[i]) * b.limbs[j] +
                                    carry;
            r.limbs[i + j] = static_cast<std::uint64_t>(cur);
            carry = cur >> 64;
        }
        std::size_t k = i + L;
        while (carry != 0 && k < 2 * L) {
            unsigned __int128 cur = static_cast<unsigned __int128>(r.limbs[k]) + carry;
            r.limbs[k] = static_cast<std::uint64_t>(cur);
            carry = cur >> 64;
            ++k;
        }
    }
    return r;
}

// -----------------------------------------------------------------------------
// Remainder by binary long division: x mod m.
// -----------------------------------------------------------------------------
template <std::size_t L>
BigInt<L> mod_wide(const BigInt<2 * L>& x, const BigInt<L>& m) {
    if (m.is_zero()) throw std::runtime_error("mod by zero");
    BigInt<L> r;
    std::size_t bits = x.bit_length();
    for (std::size_t i = bits; i-- > 0;) {
        r.shl1();
        if (x.bit(i)) r.limbs[0] |= 1ULL;
        if (r >= m) r = sub(r, m);
    }
    return r;
}

template <std::size_t L>
BigInt<L> mul_mod(const BigInt<L>& a, const BigInt<L>& b, const BigInt<L>& m) {
    return mod_wide<L>(mul_wide(a, b), m);
}

// -----------------------------------------------------------------------------
// Modular exponentiation.
// -----------------------------------------------------------------------------
template <std::size_t L>
BigInt<L> pow_mod(BigInt<L> base, const BigInt<L>& exp, const BigInt<L>& m) {
    if (m.is_zero()) throw std::runtime_error("pow_mod modulus is zero");
    BigInt<L> result = BigInt<L>::one();
    std::size_t bits = exp.bit_length();
    for (std::size_t i = bits; i-- > 0;) {
        result = mul_mod<L>(result, result, m);
        if (exp.bit(i)) result = mul_mod<L>(result, base, m);
    }
    return result;
}

// -----------------------------------------------------------------------------
// Binary GCD.
// -----------------------------------------------------------------------------
template <std::size_t L>
BigInt<L> gcd_binary(BigInt<L> u, BigInt<L> v) {
    if (u.is_zero()) return v;
    if (v.is_zero()) return u;

    std::size_t shift = 0;
    while (u.is_even() && v.is_even()) {
        u.shr1();
        v.shr1();
        ++shift;
    }
    while (u.is_even()) u.shr1();

    do {
        while (v.is_even()) v.shr1();
        if (cmp(u, v) > 0) std::swap(u, v);
        v = sub(v, u);
    } while (!v.is_zero());

    while (shift--) u.shl1();
    return u;
}

// -----------------------------------------------------------------------------
// Widen / narrow helpers.
// -----------------------------------------------------------------------------
template <std::size_t OUT, std::size_t IN>
BigInt<OUT> widen(const BigInt<IN>& x) {
    static_assert(OUT >= IN, "widen() requires OUT >= IN");
    BigInt<OUT> r;
    for (std::size_t i = 0; i < IN; ++i) r.limbs[i] = x.limbs[i];
    return r;
}

template <std::size_t OUT, std::size_t IN>
BigInt<OUT> narrow(const BigInt<IN>& x) {
    static_assert(OUT <= IN, "narrow() requires OUT <= IN");
    BigInt<OUT> r;
    for (std::size_t i = 0; i < OUT; ++i) r.limbs[i] = x.limbs[i];
    return r;
}

// -----------------------------------------------------------------------------
// Modular inverse via binary extended Euclid.
// We keep coefficients in a one-limb-wider type so x + m fits safely.
// -----------------------------------------------------------------------------
template <std::size_t L>
BigInt<L> mod_inverse(const BigInt<L>& a, const BigInt<L>& m) {
    using W = BigInt<L + 1>;

    if (m.is_zero()) throw std::runtime_error("mod_inverse modulus is zero");
    if (a.is_zero()) throw std::runtime_error("mod_inverse of zero");

    W u = widen<L + 1>(a);
    W v = widen<L + 1>(m);
    W mW = widen<L + 1>(m);

    W x1 = W::one();
    W x2 = W::zero();

    while (!(u == W::one()) && !(v == W::one())) {
        while (u.is_even()) {
            u.shr1();
            if (x1.is_even()) {
                x1.shr1();
            } else {
                x1 = add(x1, mW);
                x1.shr1();
            }
        }

        while (v.is_even()) {
            v.shr1();
            if (x2.is_even()) {
                x2.shr1();
            } else {
                x2 = add(x2, mW);
                x2.shr1();
            }
        }

        if (u >= v) {
            u = sub(u, v);
            if (x1 >= x2) x1 = sub(x1, x2);
            else {
                x1 = add(x1, mW);
                x1 = sub(x1, x2);
            }
        } else {
            v = sub(v, u);
            if (x2 >= x1) x2 = sub(x2, x1);
            else {
                x2 = add(x2, mW);
                x2 = sub(x2, x1);
            }
        }
    }

    W r = (u == W::one()) ? x1 : x2;
    return narrow<L>(r);
}

// -----------------------------------------------------------------------------
// GMP conversions and prime generation.
// GMP is used only here.
// -----------------------------------------------------------------------------
template <std::size_t L>
BigInt<L> from_mpz(const mpz_class& z) {
    BigInt<L> r;
    std::vector<std::uint64_t> buf(L, 0);
    std::size_t count = 0;
    mpz_export(buf.data(), &count, -1, sizeof(std::uint64_t), 0, 0, z.get_mpz_t());
    if (count > L) throw std::runtime_error("from_mpz: integer does not fit");
    for (std::size_t i = 0; i < count; ++i) r.limbs[i] = buf[i];
    return r;
}

template <std::size_t L>
mpz_class to_mpz(const BigInt<L>& x) {
    mpz_class z;
    mpz_import(z.get_mpz_t(), L, -1, sizeof(std::uint64_t), 0, 0, x.limbs.data());
    return z;
}

template <std::size_t L>
BigInt<L> random_big(std::mt19937_64& rng) {
    BigInt<L> r;
    for (std::size_t i = 0; i < L; ++i) r.limbs[i] = rng();
    return r;
}

template <std::size_t L>
BigInt<L> random_below(std::mt19937_64& rng, const BigInt<L>& limit) {
    BigInt<L> r;
    do {
        r = random_big<L>(rng);
    } while (r >= limit);
    return r;
}

template <std::size_t L>
BigInt<L> random_prime(gmp_randstate_t state) {
    constexpr unsigned PRIME_BITS = static_cast<unsigned>(L * 64);
    mpz_class p;
    while (true) {
        mpz_urandomb(p.get_mpz_t(), state, PRIME_BITS);
        mpz_setbit(p.get_mpz_t(), PRIME_BITS - 1);
        mpz_setbit(p.get_mpz_t(), 0);
        mpz_nextprime(p.get_mpz_t(), p.get_mpz_t());
        if (mpz_sizeinbase(p.get_mpz_t(), 2) == PRIME_BITS) break;
    }
    return from_mpz<L>(p);
}

// -----------------------------------------------------------------------------
// RSA key structure.
// -----------------------------------------------------------------------------
using PrimeInt = BigInt<PRIME_LIMBS>;
using ModInt   = BigInt<MOD_LIMBS>;

struct RSAKeyPair {
    ModInt n;
    ModInt e;
    ModInt d;
    ModInt phi;
    PrimeInt p;
    PrimeInt q;
};

RSAKeyPair make_rsa_keypair() {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, static_cast<unsigned long>(
        std::chrono::high_resolution_clock::now().time_since_epoch().count()
    ));

    PrimeInt p = random_prime<PRIME_LIMBS>(state);
    PrimeInt q = random_prime<PRIME_LIMBS>(state);
    while (p == q) q = random_prime<PRIME_LIMBS>(state);

    ModInt n   = narrow<MOD_LIMBS>(mul_wide(p, q));
    PrimeInt p1 = sub(p, PrimeInt::one());
    PrimeInt q1 = sub(q, PrimeInt::one());
    ModInt phi = narrow<MOD_LIMBS>(mul_wide(p1, q1));

    // Small, standard public exponent.
    ModInt e(65537ULL);
    while (gcd_binary(e, phi) != ModInt::one()) {
        mpz_class ez = to_mpz(e);
        mpz_nextprime(ez.get_mpz_t(), ez.get_mpz_t());
        e = from_mpz<MOD_LIMBS>(ez);
    }

    ModInt d = mod_inverse(e, phi);

    gmp_randclear(state);
    return RSAKeyPair{n, e, d, phi, p, q};
}

// -----------------------------------------------------------------------------
// RSA encryption / decryption.
// -----------------------------------------------------------------------------
template <std::size_t L>
BigInt<L> rsa_encrypt(const BigInt<L>& m, const BigInt<L>& e, const BigInt<L>& n) {
    return pow_mod<L>(m, e, n);
}

template <std::size_t L>
BigInt<L> rsa_decrypt(const BigInt<L>& c, const BigInt<L>& d, const BigInt<L>& n) {
    return pow_mod<L>(c, d, n);
}

// -----------------------------------------------------------------------------
// Timing collection.
// -----------------------------------------------------------------------------
template <std::size_t L>
double measure_decrypt_ns(const BigInt<L>& c, const BigInt<L>& d, const BigInt<L>& n,
                          int repetitions, std::uint64_t& checksum) {
    using clock = std::chrono::high_resolution_clock;
    BigInt<L> out;
    auto t0 = clock::now();
    for (int i = 0; i < repetitions; ++i) {
        out = rsa_decrypt<L>(c, d, n);
        checksum ^= out.limbs[0];
    }
    auto t1 = clock::now();
    auto total = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
    return static_cast<double>(total) / static_cast<double>(repetitions);
}

template <std::size_t L>
std::vector<BigInt<L>> generate_cipher_samples(const BigInt<L>& n,
                                               const BigInt<L>& e,
                                               std::size_t sample_count) {
    std::mt19937_64 rng(0xC0FFEEULL);
    std::vector<BigInt<L>> out;
    out.reserve(sample_count);
    for (std::size_t i = 0; i < sample_count; ++i) {
        BigInt<L> m = random_below<L>(rng, n);
        out.push_back(rsa_encrypt<L>(m, e, n));
    }
    return out;
}

template <std::size_t L>
std::vector<double> measure_cipher_times(const std::vector<BigInt<L>>& ciphers,
                                         const BigInt<L>& d,
                                         const BigInt<L>& n,
                                         int repetitions,
                                         std::uint64_t& checksum) {
    std::vector<double> times;
    times.reserve(ciphers.size());
    for (const auto& c : ciphers) {
        times.push_back(measure_decrypt_ns<L>(c, d, n, repetitions, checksum));
    }
    return times;
}

// -----------------------------------------------------------------------------
// Toy Kocher-style attack.
// For each candidate prefix we time a partial square-and-multiply execution on
// every sample ciphertext. Then we keep the candidates with the smallest
// residual variance.
// -----------------------------------------------------------------------------
template <std::size_t L>
struct Candidate {
    BigInt<L> d_guess;
    double score = 0.0;
};

template <std::size_t L>
double mean(const std::vector<double>& v) {
    double s = 0.0;
    for (double x : v) s += x;
    return s / static_cast<double>(v.size());
}

template <std::size_t L>
double variance(const std::vector<double>& v) {
    if (v.empty()) return 0.0;
    double m = mean<L>(v);
    double s = 0.0;
    for (double x : v) {
        double d = x - m;
        s += d * d;
    }
    return s / static_cast<double>(v.size());
}

template <std::size_t L>
double time_pow_mod_ns(const BigInt<L>& base, const BigInt<L>& exp, const BigInt<L>& n) {
    using clock = std::chrono::high_resolution_clock;
    auto t0 = clock::now();
    (void)rsa_encrypt<L>(base, exp, n);
    auto t1 = clock::now();
    return static_cast<double>(std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count());
}

template <std::size_t L>
double candidate_score(const BigInt<L>& exp_guess,
                       const std::vector<BigInt<L>>& ciphers,
                       const std::vector<double>& measured_ns,
                       const BigInt<L>& n) {
    std::vector<double> residuals;
    residuals.reserve(ciphers.size());
    for (std::size_t i = 0; i < ciphers.size(); ++i) {
        double predicted = time_pow_mod_ns<L>(ciphers[i], exp_guess, n);
        residuals.push_back(measured_ns[i] - predicted);
    }
    return variance<L>(residuals);
}

template <std::size_t L>
std::vector<Candidate<L>> kocher_attack(const std::vector<BigInt<L>>& ciphers,
                                        const std::vector<double>& measured_ns,
                                        const BigInt<L>& n,
                                        std::size_t d_bit_length,
                                        std::size_t keep_candidates) {
    std::vector<Candidate<L>> candidates;
    candidates.push_back(Candidate<L>{BigInt<L>::zero(), 0.0});
    candidates[0].d_guess.set_bit(d_bit_length - 1, true); // top bit of d
    candidates[0].score = candidate_score<L>(candidates[0].d_guess, ciphers, measured_ns, n);

    for (std::size_t bit = d_bit_length - 1; bit-- > 0;) {
        std::vector<Candidate<L>> next;
        next.reserve(candidates.size() * 2);

        for (const auto& cand : candidates) {
            for (int guess = 0; guess <= 1; ++guess) {
                Candidate<L> c = cand;
                c.d_guess.set_bit(bit, guess != 0);
                c.score = candidate_score<L>(c.d_guess, ciphers, measured_ns, n);
                next.push_back(c);
            }
        }

        std::sort(next.begin(), next.end(), [](const auto& a, const auto& b) {
            return a.score < b.score;
        });
        if (next.size() > keep_candidates) next.resize(keep_candidates);
        candidates = std::move(next);
    }

    return candidates;
}

// -----------------------------------------------------------------------------
// Demo main.
// argv[1] = number of samples
// argv[2] = repetitions per measured decryption
// argv[3] = number of candidates to keep during the attack
// -----------------------------------------------------------------------------
int main(int argc, char** argv) {
    std::size_t sample_count   = (argc > 1) ? static_cast<std::size_t>(std::stoull(argv[1])) : 12;
    int repetitions            = (argc > 2) ? std::stoi(argv[2]) : 6;
    std::size_t keep_candidates = (argc > 3) ? static_cast<std::size_t>(std::stoull(argv[3])) : 4;

    std::cout << "Generating RSA key pair...\n";
    RSAKeyPair key = make_rsa_keypair();

    std::cout << "n   = 0x" << key.n.to_hex() << "\n";
    std::cout << "e   = 0x" << key.e.to_hex() << "\n";
    std::cout << "d   = 0x" << key.d.to_hex() << "\n";
    std::cout << "phi = 0x" << key.phi.to_hex() << "\n";

    std::cout << "\nGenerating ciphertext samples and measuring decrypt times...\n";
    auto ciphers = generate_cipher_samples<MOD_LIMBS>(key.n, key.e, sample_count);

    std::uint64_t checksum = 0;
    auto measured = measure_cipher_times<MOD_LIMBS>(ciphers, key.d, key.n, repetitions, checksum);

    double avg = mean<MOD_LIMBS>(measured);
    std::cout << "Average measured decrypt time: " << avg << " ns\n";
    std::cout << "Checksum (anti-optimization guard): 0x" << std::hex << checksum << std::dec << "\n";

    std::size_t d_bits = key.d.bit_length();
    std::cout << "\nRunning toy Kocher-style attack on " << d_bits << " bits...\n";
    auto best = kocher_attack<MOD_LIMBS>(ciphers, measured, key.n, d_bits, keep_candidates);

    std::cout << "\nBest candidates after pruning:\n";
    for (std::size_t i = 0; i < best.size(); ++i) {
        std::cout << "  #" << i
                  << "  score=" << best[i].score
                  << "  d_guess=0x" << best[i].d_guess.to_hex() << "\n";
    }

    std::cout << "\nActual d      = 0x" << key.d.to_hex() << "\n";
    std::cout << "Top candidate  = 0x" << best.front().d_guess.to_hex() << "\n";
    std::cout << "Done.\n";
    return 0;
}
