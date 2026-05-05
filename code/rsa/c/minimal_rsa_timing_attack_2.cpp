// (updated with progress printing + bit display)
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

#ifndef MOD_LIMBS
#define MOD_LIMBS 4
#endif

static_assert(MOD_LIMBS % 2 == 0, "MOD_LIMBS must be even");
constexpr std::size_t PRIME_LIMBS = MOD_LIMBS / 2;

template <std::size_t L>
struct BigInt {
    std::array<std::uint64_t, L> limbs{};

    BigInt() = default;
    explicit BigInt(std::uint64_t v) { limbs.fill(0); limbs[0] = v; }

    static BigInt zero() { return BigInt(0); }
    static BigInt one() { return BigInt(1); }

    bool is_zero() const { for (auto w: limbs) if (w) return false; return true; }
    bool is_even() const { return !(limbs[0] & 1ULL); }

    std::size_t bit_length() const {
        for (std::size_t i=L;i-->0;) if (limbs[i]) return i*64 + (64-__builtin_clzll(limbs[i]));
        return 0;
    }

    bool bit(std::size_t i) const {
        if (i/64>=L) return false;
        return (limbs[i/64]>>(i%64))&1ULL;
    }

    void set_bit(std::size_t i,bool v){ if(i/64<L){ if(v) limbs[i/64]|=(1ULL<<(i%64)); else limbs[i/64]&=~(1ULL<<(i%64));}}

    std::string to_bits() const {
        std::string s;
        std::size_t bits = bit_length();
        for (std::size_t i = bits; i-- > 0;) s += bit(i)?'1':'0';
        return s.empty()?"0":s;
    }
};

// ---- minimal ops (same as before, shortened) ----
template <std::size_t L> int cmp(const BigInt<L>&a,const BigInt<L>&b){for(size_t i=L;i-->0;)if(a.limbs[i]!=b.limbs[i])return a.limbs[i]<b.limbs[i]?-1:1;return 0;}
template <std::size_t L> bool operator>=(const BigInt<L>&a,const BigInt<L>&b){return cmp(a,b)>=0;}

template <std::size_t L>
BigInt<L> sub(const BigInt<L>& a, const BigInt<L>& b)
{
    BigInt<L> r;
    uint64_t borrow = 0;

    for (size_t i = 0; i < L; ++i)
    {
        __int128 ai = a.limbs[i];
        __int128 bi = (__int128)b.limbs[i] + borrow;

        if (ai >= bi)
        {
            r.limbs[i] = (uint64_t)(ai - bi);
            borrow = 0;
        }
        else
        {
            r.limbs[i] = (uint64_t)(((__int128)1 << 64) + ai - bi);
            borrow = 1;
        }
    }

    return r;
}
template <std::size_t L>
BigInt<2*L> mul_wide(const BigInt<L>&a,const BigInt<L>&b){BigInt<2*L>r;for(size_t i=0;i<L;++i){__int128 c=0;for(size_t j=0;j<L;++j){__int128 cur=r.limbs[i+j]+(__int128)a.limbs[i]*b.limbs[j]+c;r.limbs[i+j]=cur;c=cur>>64;}r.limbs[i+L]+=c;}return r;}

template <std::size_t L>
BigInt<L> mod(const BigInt<2*L>&x,const BigInt<L>&m){BigInt<L>r;for(size_t i=x.bit_length();i-->0;){for(int k=L-1;k>=0;--k){r.limbs[k]<<=1;if(k&& (r.limbs[k-1]>>63)) r.limbs[k]|=1;} if(x.bit(i)) r.limbs[0]|=1; if(r>=m) r=sub(r,m);}return r;}

template <std::size_t L>
BigInt<L> mul_mod(const BigInt<L>&a,const BigInt<L>&b,const BigInt<L>&m){return mod<L>(mul_wide(a,b),m);} 

template <std::size_t L>
BigInt<L> pow_mod(BigInt<L> base,const BigInt<L>&exp,const BigInt<L>&m){BigInt<L>res=BigInt<L>::one();for(size_t i=exp.bit_length();i-->0;){res=mul_mod(res,res,m);if(exp.bit(i))res=mul_mod(res,base,m);}return res;}

// ---- RSA ----
using PrimeInt = BigInt<PRIME_LIMBS>;
using ModInt = BigInt<MOD_LIMBS>;

struct RSAKeyPair{ModInt n,e,d,phi;PrimeInt p,q;};

// GMP helpers

template <std::size_t L>
BigInt<L> from_mpz(const mpz_class& z){BigInt<L>r;std::vector<uint64_t>b(L);size_t c=0;mpz_export(b.data(),&c,-1,8,0,0,z.get_mpz_t());for(size_t i=0;i<c;++i)r.limbs[i]=b[i];return r;}

template <std::size_t L>
mpz_class to_mpz(const BigInt<L>& x){mpz_class z;mpz_import(z.get_mpz_t(),L,-1,8,0,0,x.limbs.data());return z;}

PrimeInt random_prime(gmp_randstate_t st){mpz_class p;while(true){mpz_urandomb(p.get_mpz_t(),st,PRIME_LIMBS*64);mpz_setbit(p.get_mpz_t(),PRIME_LIMBS*64-1);mpz_setbit(p.get_mpz_t(),0);mpz_nextprime(p.get_mpz_t(),p.get_mpz_t());if(mpz_sizeinbase(p.get_mpz_t(),2)==PRIME_LIMBS*64)break;}return from_mpz<PRIME_LIMBS>(p);} 

// naive inverse via GMP (keep minimal focus on attack)
ModInt mod_inverse(const ModInt&a,const ModInt&m){mpz_class A=to_mpz(a),M=to_mpz(m),inv;mpz_invert(inv.get_mpz_t(),A.get_mpz_t(),M.get_mpz_t());return from_mpz<MOD_LIMBS>(inv);} 

RSAKeyPair make_rsa(){gmp_randstate_t st;gmp_randinit_default(st);gmp_randseed_ui(st,time(NULL));
    auto p=random_prime(st),q=random_prime(st);while(cmp(p,q)==0)q=random_prime(st);
    // n = p*q (no reduction!)
    auto n_wide = mul_wide(p,q);
    ModInt n; for(size_t i=0;i<MOD_LIMBS;++i) n.limbs[i]=n_wide.limbs[i];
    auto phi_wide = mul_wide(sub(p,PrimeInt(1)),sub(q,PrimeInt(1)));
    ModInt phi; for(size_t i=0;i<MOD_LIMBS;++i) phi.limbs[i]=phi_wide.limbs[i];
    ModInt e(65537);
    ModInt d=mod_inverse(e,phi);
    return {n,e,d,phi,p,q};}

// ---- timing ----

template <std::size_t L>
double measure(const BigInt<L>&c,const BigInt<L>&d,const BigInt<L>&n,int rep){auto t0=std::chrono::high_resolution_clock::now();for(int i=0;i<rep;++i)pow_mod(c,d,n);auto t1=std::chrono::high_resolution_clock::now();return std::chrono::duration_cast<std::chrono::nanoseconds>(t1-t0).count()/double(rep);} 

// ---- attack ----

template <std::size_t L>
double variance(const std::vector<double>&v){double m=0;for(double x:v)m+=x;m/=v.size();double s=0;for(double x:v){double d=x-m;s+=d*d;}return s/v.size();}

template <std::size_t L>
double score(const BigInt<L>& g,
             const std::vector<BigInt<L>>& c,
             const std::vector<double>& t,
             const BigInt<L>& n)
{
    double s = 0.0, ss = 0.0;
    for (size_t i = 0; i < c.size(); ++i) {
        auto t0 = std::chrono::high_resolution_clock::now();
        pow_mod(c[i], g, n);
        auto t1 = std::chrono::high_resolution_clock::now();
        double r = t[i] - std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
        s += r;
        ss += r * r;
    }
    return ss / c.size() - (s / c.size()) * (s / c.size());
}

int main(int argc,char**argv){
    size_t N=argc>1?std::stoull(argv[1]):32;
    int rep=argc>2?std::stoi(argv[2]):4;
    size_t keep=argc>3?std::stoull(argv[3]):4;

    std::cout<<"Generating RSA...\n";
    auto k=make_rsa();

    std::cout<<"n="<<k.n.to_bits()<<"\n";
    std::cout<<"d="<<k.d.to_bits()<<"\n";

    std::vector<ModInt> ciphers;
    std::vector<double> times;

    std::mt19937_64 rng(0);

    for(size_t i=0;i<N;++i){
        ModInt m; for(auto &x:m.limbs)x=rng();
        auto c=pow_mod(m,k.e,k.n);
        ciphers.push_back(c);
        times.push_back(measure(c,k.d,k.n,rep));

        std::cout<<"Collecting samples "<<i+1<<"/"<<N<<"\r"<<std::flush;
    }
    std::cout<<"\n";

    size_t bits=k.d.bit_length();

    std::vector<ModInt> cand(1);
    cand[0].set_bit(bits-1,1);

    for (size_t b = bits - 1; b-- > 0; ) {
        std::vector<std::pair<ModInt, double>> next;

        for (auto &c : cand) {
            ModInt g0 = c, g1 = c;
            g0.set_bit(b, 0);
            g1.set_bit(b, 1);
            next.emplace_back(g0, score(g0, ciphers, times, k.n));
            next.emplace_back(g1, score(g1, ciphers, times, k.n));
        }

        std::sort(next.begin(), next.end(),
                [](auto &a, auto &b) { return a.second < b.second; });

        cand.clear();
        for (size_t i = 0; i < std::min(keep, next.size()); ++i)
            cand.push_back(next[i].first);

        bool guess = cand[0].bit(b);
        bool ok = (guess == k.d.bit(b));

        std::cout << "bit " << b
                << ": " << guess
                << " (true " << k.d.bit(b) << ")"
                << " score=" << next[0].second
                << " " << (ok ? "OK" : "BAD")
                << '\n';
    }

    std::cout<<"Final guess: "<<cand[0].to_bits()<<"\n";
    std::cout<<"Real d:      "<<k.d.to_bits()<<"\n";
}
