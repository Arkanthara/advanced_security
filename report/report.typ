// Main report file
#import "template.typ": make-report, report-footnote
#import "metadata.typ": my-report
#import "@preview/cetz:0.3.1": canvas, draw, tree

// Main content
#show: make-report.with(my-report)
#show raw.where(block: true): set block(fill: luma(240), inset: 1em, radius: 0.5em, width: 100%)
// #show raw.where(block: false): set block(fill: luma(240), inset: 1em, radius: 0.5em, width: 100%)
// #show raw.where(block: false): box.with(
//   fill: rgb("#e573e927"),
//   inset: (x: 3pt, y: 0pt),
//   outset: (y: 3pt),
//   radius: 2pt,
// )

= Introduction

The cryptography goal is to ensure the confidentiality, integrity, and authenticity of information, and it has become increasingly important in the digital age with the rise of the internet and digital communication where sensitive information is frequently transmitted.
To achieve these goals, various cryptographic algorithms and protocols have been developed, including symmetric and asymmetric encryption, hashing, and digital signatures.
These algorithms are based on mathematical problems that are computationally difficult to solve, such as factoring large integers or computing discrete logarithms, which provide the basis for their security since they are believed to be infeasible to break with current computational resources.

However, although these algorithms are designed to be secure against direct attacks, the implementation of these algorithms can introduce vulnerabilities that can be exploited by attackers.
The vulnerabilities reside in the way the algorithms are implemented and executed, rather than in the algorithms themselves.
Indeed, attackers can exploit side channels, which are unintended information leaks that occur during the execution of cryptographic algorithms such as timing information, power consumption, electromagnetic emissions, or even sound.
By analyzing these side channels, attackers can gain insights into the internal workings of the cryptographic algorithm and potentially recover sensitive information such as secret keys.

In this report, we will focus on timing attacks, which are a type of side-channel attack that exploits the time it takes for a cryptographic algorithm to execute.
Timing attacks can be used to recover secret keys or other sensitive information by measuring the time it takes for a cryptographic operation to complete and analyzing the variations in timing based on different inputs or conditions.

= Timing attacks on RSA

RSA is a widely used asymmetric encryption algorithm that relies on the difficulty of factoring large integers to provide security.
It allows in particular for sharing a symmetric key securely over an insecure channel, enabling secure communication between parties without the need for a pre-shared secret key.

The base principle of RSA resides in the use of a pair of keys: a public key for encryption and a private key for decryption.
The RSA algorithm consists of three main steps: key generation, encryption, and decryption.

== RSA basics

The key generation process involves selecting two large prime numbers, $p$ and $q$, and computing their product $n = p times q$, which serves as the modulus for both the public and private keys.
The choice of $p$ and $q$ is crucial for the security of RSA, as the difficulty of factoring $n$ into its prime factors is what provides the security of the algorithm.
Indeed, if an attacker can factor $n$ into $p$ and $q$, they can compute the private key and break the encryption.

The algorithm of key generation can be summarized as follows:

1. Choose two distinct large prime numbers $p$ and $q$.
2. Compute $n = p times q$ and $phi(n) = (p-1)(q-1)$.
3. Choose an integer $e$ such that
    - $1 < e < phi(n)$
    - $gcd(e, phi(n)) = 1$
4. Compute $d$ such that $e dot d equiv 1 mod phi(n)$.

The public key consists of the pair $(n, e)$, while the private key consists of the pair $(n, d)$.

The encryption process consists of taking a plaintext message $m$ and computing the ciphertext $c = m^e mod n$ using the public key, and the decryption process consists of taking the ciphertext $c$ and computing the plaintext message $m = c^d mod n$ using the private key.

// By construction, we have $c^d mod n = m^(e d) mod n$. As $e dot d equiv 1 mod phi(n)$, we can write $e dot d = 1 + k times phi(n)$ for some integer $k$, and thus $c^d mod n = m^(1 + k times phi(n)) mod n = m times (m^phi(n))^k mod n$.
// By Euler's theorem, we have $m^phi(n) equiv 1 mod n$ for any integer $m$ that is coprime to $n$, and thus $c^d mod n = m times 1^k mod n = m mod n$, which means that the decryption process correctly recovers the original plaintext message.

For convenience, we will use the following notations throughout the report:
- $n$: the modulus, which is the product of two large prime numbers $p$ and $q$.
- $e$: the public exponent, which is an integer that is coprime to $phi(n)$.
- $d$: the private exponent, which is an integer such that $e dot d equiv 1 mod phi(n)$.
- $m$: the plaintext message, which is an integer that is less than $n$.
- $c$: the ciphertext, which is an integer that is less than $n$.

```python
%| echo: false
import os
import timeit
import random
import numpy as np
from tqdm import tqdm
import matplotlib.pyplot as plt
```
```python
%| echo: false
class RSA:
    """
    RSA implementation for encryption, signature and station-to-station key exchange.
    """

    def __init__(self, private_key: int = None, public_key: int = None, n: int = None, fast_exp: callable = None) -> None:
        self.private_key = private_key
        self.public_key = public_key
        self.n = n
        self.challenge = "Bravo ! Je suis épousplouffé par ta maîtrise du timing attack sur RSA !"
        self.fast_exp = fast_exp if fast_exp is not None else self._default_fast_exp
    
    def copy(self):
        return RSA(self.private_key, self.public_key, self.n, self.fast_exp)

    def _default_fast_exp(self, y: int, x: int, n: int) -> int:
        """Apply fast exponentiation for y^x modulo n"""
        s = 1
        y %= n

        while x > 0:
            if (x % 2) == 1:
                s = (s * y) % n
            y = (y * y) % n
            x = x >> 1

        return s

    def setKeys(self, private_key: int, public_key: int, n: int) -> None:
        self.private_key = private_key
        self.public_key = public_key
        self.n = n

    def getKeys(self) -> list:
        return [self.public_key, self.n], [self.private_key, self.n]
    
    def exportPublicKey(self) -> list:
        return [self.public_key, self.n]

    def createKeyPair(self, size: int) -> list:
        p = self.primary_nb_generator(2**(size//2 - 1), 2**(size//2))
        q = self.primary_nb_generator(2**(size//2 - 1), 2**(size//2))
        n, e, d = self.key_generator(p, q, size=size)
        self.setKeys(d, e, n)
        return [n, e, d]

    def encrypt(self, message: int) -> int:
        return self.fast_exp(message, self.public_key, self.n)

    def decrypt(self, cipher: int, private_key: int = None) -> int:
        if private_key is not None:
            return self.fast_exp(cipher, private_key, self.n)
        return self.fast_exp(cipher, self.private_key, self.n)
    
    def createChallenge(self) -> int:
        challenge_int = int.from_bytes(self.challenge.encode(), 'big')
        self.challenge = self.encrypt(challenge_int)
        return self.challenge
    
    def decryptChallenge(self, tested_key: int) -> str:
        decrypted_challenge_int = self.decrypt(self.challenge, private_key=tested_key)
        decrypted_challenge_bytes = decrypted_challenge_int.to_bytes((decrypted_challenge_int.bit_length() + 7) // 8, 'big')
        return decrypted_challenge_bytes.decode()

    def fermat_test(self, n: int) -> bool:
        """
        Check if a number is primary by running Fermat test.
        """
        for _ in range(20):
            alpha = random.randint(2, n - 1)
            if self.fast_exp(alpha, n - 1, n) != 1:
                return False
        return True

    def primary_nb_generator(self, a: int, b: int, safe_prime: bool = False) -> int:
        """
        Generate primary number in range a, b

        Parameters
        ----------
        a : int
            lower bound
        b : int
            upper bound
        safe_prime : bool
            Generate primary number p with (p - 1) / 2 also primary

        Returns
        -------
        int
            Primary number generated

        """
        while True:
            p = random.randint(a, b)
            if self.fermat_test(p):
                if safe_prime:
                    if self.fermat_test((p - 1) / 2):
                        return p
                else:
                    return p

    def Euclide(self, a: int, b: int) -> list:
        """
        Euclide's extended algorithm, used to find decryption exponent d for RSA
        Return a list [pgcd(a, b), inverse of a mod b, inverse of b mod a]

        """
        if b > a:
            a, b = b, a  # swap

        r_0, r_1 = a, b
        s_0, s_1 = 1, 0
        t_0, t_1 = 0, 1

        while r_1 != 0:
            q = r_0 // r_1
            r_0, r_1 = r_1, r_0 - q * r_1
            s_0, s_1 = s_1, s_0 - q * s_1
            t_0, t_1 = t_1, t_0 - q * t_1

        return [r_0, s_0 % b, t_0 % a]

    def key_generator(self, p: int = 0, q: int = 0, e: int = 0, size: int = 512) -> list:
        """
        Generate public and private key for RSA
        """
        if p == 0:
            p = self.primary_nb_generator(2**(size//2 - 1), 2**(size//2))
        if q == 0:
            q = self.primary_nb_generator(2**(size//2 - 1), 2**(size//2))

        assert self.fermat_test(p), "p is not primary"
        assert self.fermat_test(q), "q is not primary"
        n = p * q
        phi_n = (p - 1) * (q - 1)

        if e != 0:
            pgcd, _, d = self.Euclide(phi_n, e)
            assert pgcd == 1, "pgcd(phi_n, e) is not equal to 1, so no private key found !"

        else:
            # Find a primary number e with phi_n
            while True:
                e = random.randint(2**(size - 1), 2**(size))
                pgcd, _, d = self.Euclide(phi_n, e)

                # If primary number with phi_n, claim public key
                if pgcd == 1:
                    break
        return n, e, d

def collect_samples(
    RSA_instance: RSA,
    num_samples: int = 1000,
    num_repetitions: int = 10000,
    private_key: int = None,
    progress_bar: bool = True,
    warmup_reps: int = 200,
) -> np.ndarray:
    """Collect timing samples for RSA decryption.

    Each sample is a (ciphertext, min_time_ns) pair. The minimum over
    num_repetitions is used because OS jitter can only ADD latency —
    the minimum is therefore the best estimate of the true computation
    time, as established in the timing attack literature (Kocher 1996,
    Brumley & Boneh 2003).

    Parameters
    ----------
    RSA_instance : RSA
        An instance of the RSA class.
    num_samples : int
        The number of (ciphertext, time) pairs to collect.
    num_repetitions : int
        The number of repetitions per sample. More = better chance of
        one clean, uninterrupted measurement.
    private_key : int, optional
        The private key to use. Defaults to RSA_instance.private_key.
    progress_bar : bool, default=True
        Whether to display a tqdm progress bar.
    warmup_reps : int, default=200
        Warm-up decryptions to stabilize CPU caches and branch predictor.

    Returns
    -------
    np.ndarray
        Array of shape (num_samples, 2): columns are [ciphertext, min_time_ns].
    """
    key = private_key if private_key is not None else RSA_instance.private_key
    n = RSA_instance.n
    decrypt_fn = RSA_instance.decrypt

    # --- Warm-up ---
    # Stabilise CPU caches and branch predictor before any measurement.
    # timeit handles GC disabling automatically.
    warmup_timer = timeit.Timer(
        stmt=lambda: decrypt_fn(random.randint(1, n - 1), private_key=key)
    )
    warmup_timer.timeit(number=warmup_reps)

    # --- Collection ---
    samples = np.empty((num_samples, 2), dtype=np.float64)

    for i in tqdm(range(num_samples), disable=not progress_bar, leave=False):
        cipher = random.randint(1, n - 1)

        timer = timeit.Timer(
            stmt=lambda: decrypt_fn(cipher, private_key=key)
        )

        # repeat=num_repetitions, number=1 → one wall-clock measurement
        # per decryption call, in seconds. timeit disables GC automatically.
        raw_times_ns = np.array(
            timer.repeat(repeat=num_repetitions, number=1)
        ) * 1e9

        # The minimum is the best estimator of true decryption time.
        # OS interrupts can only ADD latency, never subtract it.
        samples[i] = [cipher, raw_times_ns.min()]

    return samples

def timing_attack(
    RSA_instance: RSA,
    num_samples: int = 1000,
    num_repetitions: int = 10000,
    num_iterations: int = 10,
    num_known_bits: int = 5,
    buffer_size: int = 5,
    warmup_reps: int = 200,
    progress_bar: bool = False,
) -> tuple[np.ndarray, list[float]]:
    """
    Perform a timing attack on RSA to recover the private key.

    Uses a beam search over key hypotheses: at each iteration, two
    candidate bits (0 and 1) are tested for each key in the buffer.
    The hypothesis that minimises variance of (server_time - local_time)
    is kept, exploiting the extra multiplication in square-and-multiply
    when a key bit is 1.

    Parameters
    ----------
    RSA_instance : RSA
        An instance of the RSA class.
    num_samples : int
        Number of ciphertext/time pairs to collect per measurement.
    num_repetitions : int
        Repetitions per ciphertext inside collect_samples. More reps
        = better min() estimate. Replaces the old disable_gc flag since
        timeit now handles GC automatically.
    num_iterations : int
        Number of key bits to recover (one per iteration).
    num_known_bits : int
        Number of LSBs of the private key assumed to be known.
    buffer_size : int
        Beam width: how many candidate keys to keep at each iteration.
    warmup_reps : int
        Warm-up decryptions before any measurement (default: 200).
    progress_bar : bool
        Whether to display a progress bar during sample collection.

    Returns
    -------
    tuple[np.ndarray, list[float]]
        candidate_keys : best `buffer_size` recovered key candidates.
        error_rate     : bit error rate (%) for each candidate.
    """
    # --- Collect server reference samples (true private key) ---
    server_samples = collect_samples(
        RSA_instance,
        num_samples=num_samples,
        num_repetitions=num_repetitions,
        warmup_reps=warmup_reps,
        progress_bar=progress_bar,
    )

    # --- Beam search initialisation ---
    initial_key = RSA_instance.private_key & ((1 << num_known_bits) - 1)
    candidate_keys      = np.full(buffer_size, initial_key)
    candidate_variances = np.full(buffer_size, np.inf)

    history_keys      = np.zeros((num_iterations, buffer_size))
    history_variances = np.zeros((num_iterations, buffer_size))

    # --- Bit-by-bit recovery ---
    for i in range(num_iterations):
        tested_keys      = []
        tested_variances = []

        for key in candidate_keys:
            # Hypothesis 0: next bit is 0
            key_h0 = key
            # Hypothesis 1: next bit is 1
            key_h1 = key | (1 << (num_known_bits + i))

            for hyp_key in (key_h0, key_h1):
                hyp_samples = collect_samples(
                    RSA_instance,
                    num_samples=num_samples,
                    num_repetitions=num_repetitions,
                    private_key=hyp_key,
                    warmup_reps=warmup_reps,
                    progress_bar=progress_bar,
                )
                # Variance of time difference: drops when key prefix matches
                # the real key (the extra multiplication aligns in time)
                variance = np.var(server_samples[:, 1] - hyp_samples[:, 1])
                tested_keys.append(hyp_key)
                tested_variances.append(variance)

        tested_keys      = np.array(tested_keys)
        tested_variances = np.array(tested_variances)

        # Keep the buffer_size best hypotheses (lowest variance)
        best_indices        = np.argsort(tested_variances)[:buffer_size]
        candidate_keys      = tested_keys[best_indices]
        candidate_variances = tested_variances[best_indices]

        history_keys[i]      = candidate_keys
        history_variances[i] = candidate_variances

        # --- Per-iteration debug print ---
        best_key       = candidate_keys[0]
        bit_guessed    = (best_key >> (num_known_bits + i)) & 1
        bit_real       = (RSA_instance.private_key >> (num_known_bits + i)) & 1
        h0_var         = tested_variances[tested_keys == key_h0][0]
        h1_var         = tested_variances[tested_keys == key_h1][0]
        correct        = "✓ CORRECT" if bit_guessed == bit_real else "✗ WRONG"
        print(
            f"Iteration {i+1:>{len(str(num_iterations))}}/{num_iterations}: "
            f"bit guessed = {bit_guessed}  "
            f"(var h0 = {h0_var:.4e}, var h1 = {h1_var:.4e})  {correct}"
        )

    # --- Final error rate across all candidates ---
    error_rates = []
    print(f"\n{'─' * 40}")
    for rank, (key, variance) in enumerate(zip(candidate_keys, candidate_variances)):
        guessed_bits = (key >> num_known_bits) % (1 << num_iterations)
        real_bits    = (RSA_instance.private_key >> num_known_bits) % (1 << num_iterations)
        n_errors     = (guessed_bits ^ real_bits).bit_count()
        rate         = n_errors / num_iterations * 100
        error_rates.append(rate)
        print(f"Candidate #{rank+1}")
        print(f"  Key:        {key}")
        print(f"  Variance:   {variance:.4e}")
        print(f"  Error rate: {rate:.2f}%  ({n_errors}/{num_iterations} bits wrong)")
        print(f"{'─' * 40}")

    return candidate_keys, error_rates

def get_samples_stats(
    RSA_instance: RSA,
    d_A: int,
    num_samples: int = 10000,
    warmup_reps: int = 200,
    progress_bar: bool = True,
) -> np.ndarray:
    """
    Collect individual decryption times for a single fixed ciphertext.
    Used to inspect the timing distribution (histogram, min, spread).

    Parameters
    ----------
    RSA_instance : RSA
    d_A : int
        Private key.
    num_samples : int
        Number of individual timing measurements to collect.
    warmup_reps : int
        Warm-up iterations to stabilise caches (default: 200).
    progress_bar : bool
        Show progress bar during measurement.

    Returns
    -------
    np.ndarray shape (num_samples,), times in nanoseconds.
    """
    decrypt_fn = RSA_instance.decrypt
    n = RSA_instance.n

    # Warm-up: timeit handles GC disabling automatically
    warmup_timer = timeit.Timer(
        stmt=lambda: decrypt_fn(random.randint(1, n - 1), private_key=d_A)
    )
    warmup_timer.timeit(number=warmup_reps)

    # One measurement per call (number=1), repeated num_samples times
    # This gives us the full distribution, not a single aggregate
    timer = timeit.Timer(
        stmt=lambda: decrypt_fn(random.randint(1, n - 1), private_key=d_A)
    )

    raw = list(
        tqdm(
            (t * 1e9 for t in timer.repeat(repeat=num_samples, number=1)),
            total=num_samples,
            desc="Sampling",
            disable=not progress_bar,
            leave=False,
        )
    )

    return np.array(raw, dtype=np.float64)

def plot_distributions(samples_stats_h0: np.ndarray, samples_stats_h1: np.ndarray, title: str = "Distribution of decryption times for two hypotheses with branch prediction"):
    plt.figure(figsize=(12, 6))
    plt.suptitle(title)
    plt.subplot(1, 2, 1)
    plt.hist(samples_stats_h0, bins=200)
    plt.axvline(np.min(samples_stats_h0), color='red', linestyle='dashed', linewidth=1, label=f'Min: {np.min(samples_stats_h0):.4f} ms')
    plt.title("Hypothesis h0: the last bit is 0")
    plt.xlabel("Decryption Time")
    plt.ylabel("Frequency")
    plt.legend()
    plt.subplot(1, 2, 2)
    plt.hist(samples_stats_h1, bins=200)
    plt.axvline(np.min(samples_stats_h1), color='red', linestyle='dashed', linewidth=1, label=f'Min: {np.min(samples_stats_h1):.4f} ms')
    plt.title("Hypothesis h1: the last bit is 1")
    plt.xlabel("Decryption Time")
    plt.ylabel("Frequency")
    plt.legend()
    plt.tight_layout()
    plt.show()
```
```python
%| echo: false
#----------------------------------------------------------------------------
# Initialization of RSA parameters for the attack
#----------------------------------------------------------------------------

p_A = 13109499994810966779468866046493465498469807493634236479294124421385342920350717814807375283698575766763256101470694189234369358996750113963585617491399169
q_A = 9497561827984502554523100157901534504433126034087863778629488755692649311435921364240405549590851856701860175924335776598684751639633322074428628372725777
n_A = p_A * q_A
e_A = 4574830074548708213
m_1 = 123456789132456789
d_A = 1685394382767324790326942621450485552187209875614438478305225564629345944620726038114923060947436330701451901921041511234432041036987266468290187679773130363479895993621867708066144608084390089775045890165825736468637468786667820591136139480545376198614216373031208691260339805721685482401743494212035728605

RSA_instance = RSA()
n, e, d = RSA_instance.key_generator(p_A, q_A, e_A)
RSA_instance.setKeys(d, e, n)
```


== Variance-based timing attack

Before the exchange of symmetric keys, the client and the server need to perform an RSA encryption and decryption operation to establish a secure communication channel.
The timing of these operations can be exploited by attackers to infer information about the private key.

As mentioned earlier, the security of RSA relies on the difficulty of factoring large integers, but the implementation of RSA can introduce vulnerabilities that can be exploited by attackers.
The goal of the attacker is to recover the unknown private key $d$ thanks to the knowledge of the public key $(n, e)$ and the ability to perform encryption and decryption operations on the server using the RSA algorithm.

=== Square-and-multiply algorithm

Timing attacks on RSA exploit the fact that the time it takes to perform certain operations in the RSA algorithm can vary based on the input values and the internal state of the algorithm.
For example, the time it takes to perform the modular exponentiation operation $c^d mod n$ can vary based on the value of $d$ and the input ciphertext $c$.
Indeed, a simple implementation of the modular exponentiation operation can use a square-and-multiply algorithm, as described in the following python code:

```python
%| execute: false
def square_and_multiply(y, x, n):
  s = 1
  y %= n

  while x > 0:
      if (x % 2) == 1:
          s = (s * y) % n # Extra multiplication here when x is odd !
      y = (y * y) % n
      x = x >> 1

  return s
```

This code computes $y^x mod n$ using the square-and-multiply algorithm, which is an efficient method for performing modular exponentiation.
Indeed, computing $y^x mod n$ for very large values of $x$ is computationally expensive.

The base idea of this algorithm is that computing $y^x$ can be done by taking the binary representation of $x$, which is basically the decomposition of $x$ into powers of 2, and then iteratively computing $y^x mod n$ by taking at each step the previous result and multiplying it by $y$ if the current bit of $x$ is 1, and then squaring the input $y$.

For instance, suppose we want to compute $6^13 mod 17$.
- The binary representation of $13$ is $1101$, which corresponds to the powers of 2: $2^3 + 2^2 + 2^0$.
- We start with $s = 1$ and $y = 6$.
- For the first bit (1), we compute
  - $s = (s dot y) mod 17 = (1 dot 6) mod 17 = 6$
  - $y = y^2 mod 17 = 6^2 mod 17 = 2$.
- For the second bit (0), we compute
  - $s$ remains unchanged since the bit is 0, so $s = 6$.
  - $y = y^2 mod 17 = 2^2 mod 17 = 4$. Note that here, $y^2$ corresponds to $y^2^2 = y^(2 dot 2) = y^4$.
- For the third bit (1), we compute
  - $s = (s dot y) mod 17 = (6 dot 4) mod 17 = 24 mod 17 = 7$
  - $y = y^2 mod 17 = 4^2 mod 17 = 16$.
- For the fourth bit (1), we compute
  - $s = (s dot y) mod 17 = (7 dot 16) mod 17 = 112 mod 17 = 15$
  - $y = y^2 mod 17 = 16^2 mod 17 = 256 mod 17 = 1$.

So the result of $6^13 mod 17$ is $15$.
The efficiency of the algorithm comes from the fact that it iteratively computes $y^x mod n$ by performing small multiplication and squaring operations thanks to the modular properties instead of performing a single large exponentiation operation.

But the timing of this algorithm can vary based on the value of the exponent $x$ and the input $y$.
Indeed, as seen in the above example, the algorithm performs an extra multiplication only when the bit of $x$ is 1, which can lead to a longer execution time compared to when the bit is 0.
This variation in timing is the basis for timing attacks on RSA.

=== Exploiting timing variations

Attackers can exploit the timing variations in the square-and-multiply algorithm to recover the private key $d$ by measuring the time it takes for the server to perform decryption operations.
Note that the attacker must know the modulus $n$, which is public.

First, the attacker sends multiple random ciphertexts $c$ to the server and measures the time it takes for the server to perform the decryption operation $c^d mod n$.

Then for each bit of the private key $d$, the attacker guesses the value of the bit (0 or 1) and computes the expected timing of the decryption operation based on the guess for all the ciphertexts $c$.

Finally, the attacker subtracts his obtained timing measurements from the timing measurements obtained from the server and analyzes the variance of the obtained results.
If the variance is low, it means that the guess for the bit is correct, while if the variance is high, it means that the guess for the bit is incorrect.

By repeating this process for all the bits of the private key $d$, the attacker can recover the entire private key.

=== Mathematical analysis

==== Probability of a correct guess

We consider $N$ random ciphertexts $c_1, c_2, ..., c_N$ that the attacker sends to the server for decryption.

Let $T_i$ be the time taken for the server to perform the decryption operation $c^d mod n$ for a given ciphertext $c_i$.

Let $x_b$ be the guess for the $b$ first bits of the private key $d$.

Let $t(c_i, x_b)$ be the time taken to perform the decryption operation according to the guess $x_b$ for the $b$ first bits of $d$.

If the guess $x_b$ is correct, the timing error $T_i - t(c_i, x_b)$ will be small, indicating a good match between the observed and expected timings.
We define $F$ as the probability to observe the timing error $T_i - t(c_i, x_b)$ if the guess $x_b$ is correct.
As each timing measurement is independent, the probability of a correct guess for the $b$ first bits of $d$ is proportional to the product of the probabilities of $F$ for all the ciphertexts $c_i$:

$ P(x_b) prop product_(i=1)^N F(T_i - t(c_i, x_b)) $

Suppose that the $b - 1$ bits of $d$ are correct, and we want to guess the value of the $b$-th bit.
We note $x_b_0$ and $x_b_1$ the guesses for the $b$-th bit being 0 and 1, respectively.

The probability of having $x_b_1$ is:

$ P(x_b_1) = (product_(i=1)^N F(T_i - t(c_i, x_b_1)))/(product_(i=1)^N F(T_i - t(c_i, x_b_0)) + product_(i=1)^N F(T_i - t(c_i, x_b_1))) $

If $P(x_b_1) > 0.5$, it means that the guess $x_b_1$ is more likely to be correct than the guess $x_b_0$, and thus we can conclude that the $b$-th bit of $d$ is likely to be 1.

Concretely, computing the exact distribution of $F$ is not feasible.

==== Variance analysis

Instead of computing the exact distribution of $F$, we can analyze the variance of the timing errors for the two guesses $x_b_0$ and $x_b_1$.

Suppose the private key $d$ has $l$ bits.
The time taken for the decryption operation can be denoted as $T_i = sum_(k = 1)^l t_k + epsilon$ with $t_k$ the time taken for the $k$-th step of the algorithm and $epsilon$ representing the timing noise caused by various factors such as system load, network latency, or other sources of randomness.

Suppose that $x_(b - 1)$ is known to be correct.
The attacker can compute the time taken for each step of the first $b - 1$ bits as $sum_(k = 1)^(b - 1) t_k$.

The time difference is then:

$ T_i - t(c_i, x_(b - 1)) = sum_k^l t_k + epsilon - sum_k^(b - 1) t_k = sum_(k = b)^l t_k + epsilon $

If the guess $x_b$ is correct, the time difference will be:

$ T_i - t(c_i, x_b) = sum_(k = b + 1)^l t_k + epsilon $

And if the guess $x_b$ is incorrect, the time difference will be:

$ T_i - t(c_i, x_b) = sum_k^l t_k + epsilon - (sum_k^(b - 1) t_k + t_b_("incorrect")) = sum_(k = b + 1)^l t_k + epsilon + (t_b_("correct") - t_b_("incorrect")) $.

We can constate that the time difference for the correct guess $x_b$ is smaller than the time difference for the incorrect guess $x_b$ by a factor of $t_b_("correct") - t_b_("incorrect")$, meaning that the variance of the time differences for the correct guess $x_b$ will be smaller than the variance of the time differences for the incorrect guess $x_b$.

So by analyzing the variance of the time differences for the two guesses $x_b_0$ and $x_b_1$, the attacker can determine which guess is more likely to be correct, and thus recover the bits of the private key $d$ one by one.

==== Impact of previous errors on the variance

Now, suppose that the $c$-th bit of $d$ is incorrect for some $c < b - 1$.
The time difference for the correct guess $x_b$ will be:

$ T_i - t(c_i, x_b) = sum_k^l t_k + epsilon - (sum_k^(c - 1) t_k + sum_(k = c)^b t_k) = sum_(k = b + 1)^l t_k + epsilon + (sum_(k = c)^b (t_k_("correct") - t_k_("incorrect"))) $

We have $t_k$ which starts to be different for the correct and incorrect guesses for all the bits from $c$ to $b$ since the intermediate steps of the algorithm will be executed differently due to the error in the guess for the $c$-th bit, leading to a different $t_k$ for all the bits from $c$ to $b$ even if the guess for the $b$-th bit is correct.

So when the guess $x_b$ has some previous errors, the variance of the correct guess will start to be similar to the variance of the incorrect guess.

This property can be exploited to detect errors in the guess for the $b$-th bit.
Indeed, attacker can keep track of the variance of the time differences and come back to a previous guess if the variance starts to be too similar for both the correct and incorrect guesses, indicating that there might be an error in the previous bits of the guess.

=== Code implementation

The code implementation was done first in Python, and then in Rust and C++ to try to reduce the noise in the timing measurements and thus increase the chances of success of the attack.

Indeed, the python implementation was not successful at all in recovering the private key due to the high noise caused by the Python interpreter and its optimizations, which totally masked the timing variations caused by the square-and-multiply algorithm.

==== Sources of noise <noise>

There are several sources of noise that can affect the timing measurements in programming languages, especially in high-level languages like Python.

===== CPU cache effects

CPU cache effects that can cause variability in the timing measurements based on the memory access patterns of the algorithm.

First, there are different levels of CPU cache (L1, L2, L3) that can store recently accessed data and instructions.

These caches are designed to speed up access to frequently used data and instructions, but they can also introduce variability in the timing measurements.
Indeed, the cache L1 is the fastest but also the smallest, while the cache L3 is the slowest but also the largest, meaning that if the data or instructions needed for the algorithm are in the cache L1, the timing measurements will be faster compared to when they are in the cache L3 or not in the cache at all.

If the data or instructions needed are not in the cache, the CPU triggers a cache miss, which means that it has to fetch the data from the main memory, leading to a significant delay in the execution of the algorithm and thus in the timing measurements.

These cache effects represent a significant source of noise in timing measurements.

===== Branch prediction

Branch prediction is a technique used by modern CPUs to improve performance by guessing the outcome of conditional statements and executing instructions based on those guesses.
When the CPU encounters a conditional statement (e.g., an if statement), it makes a guess about which branch of the code will be executed next based on past behavior and patterns.
This allows the CPU to continue executing instructions without waiting for the outcome of the conditional statement, which can improve performance.

So if the CPU correctly predicts the branch, it can continue executing instructions without interruption, but if the CPU incorrectly predicts the branch, it has to discard the incorrectly executed instructions and fetch the correct instructions, leading to a significant delay in the execution of the algorithm and thus in the timing measurements.

That's why branch prediction can cause variability in the timing measurements based on the input values and the internal state of the algorithm, as different inputs can lead to different execution paths and thus different branch predictions.

===== Garbage collection

Garbage collection is a form of automatic memory management that is used in many programming languages, including Python.
It is responsible for automatically freeing up memory that is no longer in use by the program, which can help prevent memory leaks and improve performance.

However, the garbage collector can be triggered at any time during the execution of the program.
When the garbage collector runs, it can cause significant delays in the execution of the program: it has to pause the execution of the program, scan the memory for objects that are no longer in use, and free up the memory occupied by those objects.

This can lead to significant variability in the timing measurements since the garbage collector can be triggered at different times during the execution of the algorithm, leading to different timing measurements for the same operations.

===== Multiplication optimizations

The usage of modern programming languages introduces various optimizations that can affect the timing measurements, such as the optimization of multiplication operations.

The multiplication of large integers can be optimized using different algorithms depending on the size of the numbers.
For small integers, the standard multiplication algorithm is used whereas for larger integers, more efficient algorithms such as Karatsuba or Toom-Cook can be used.

These optimizations can lead to different timing measurements for the same operations based on the size of the numbers being multiplied.

===== Other optimizations

There are also other optimizations that can be introduced by the programming language or the compiler, such as loop unrolling, instruction reordering, or just-in-time compilation, which can further introduce variability in the timing measurements.

So the sources of noise in timing measurements can be quite significant, especially in high-level programming languages like Python, and they can totally mask the timing variations caused by the square-and-multiply algorithm.

==== Reducing the impact of noise

There are several techniques that can be used to try to reduce the impact of these sources of noise in timing measurements.

Inspired by the blog post "Kocher's Timing Attack: A Journey from Theory to Practice" @kocher_jupyter, I try to implement some of them, trying to mitigate the impact of noise and thus increase the chances of success of the attack.

===== Reducing the impact of the garbage collector

As mentioned in @noise, the garbage collector is a significant source of noise in the timing measurements, so one way to reduce the noise is to disable the garbage collector during the timing measurements.

This can be done manually using the `gc` module in Python, which provides functions to enable and disable the garbage collector.
Even if this can help to reduce the noise caused by the garbage collector, it is not sufficient to extract the signal from the noise and thus distinguish between the case with the extra multiplication (key 1) and the case without the extra multiplication (key 0) since there are still other sources of noise that can affect the timing measurements.

However the right approach to perform the precise timing measurements was not to manually disable the garbage collector, but rather to use the `timeit` module in Python, which is designed to perform accurate timing measurements.

Indeed, the `timeit` module, which is a part of the Python standard library, is specifically designed for measuring the execution time of small code snippets with high precision.
It automatically handles various sources of noise, including disabling the garbage collector during the timing measurements, which can help to reduce the impact of the garbage collector on the timing measurements and thus increase the chances of success of the attack.

The @fig1 shows the comparison of timing measurements with manual management of the garbage collector (GC) and using the `timeit` module, which handles GC automatically.
It is done by repeating the timing measurements for a fixed ciphertext and fixed key, and then plotting the distribution of the timing measurements for both approaches.
We can easily see that the timing measurements obtained with the `timeit` module are much more consistent and less noisy compared to the timing measurements obtained with manual management of the garbage collector.

Indeed, with the `timeit` module, the timing measurements are more concentrated around a certain value since the pick of frequency of the timing measurements with same value is around 10 times higher than with the manual management of the garbage collector, which means that the timing measurements obtained with the `timeit` module are more consistent and less affected by noise compared to the timing measurements obtained with manual management of the garbage collector.

On top of that, the minimum timing measurement obtained with the `timeit` module is 100 times lower than the minimum timing measurement obtained with manual management of the garbage collector, which means that the `timeit` module is able to capture the true decryption time more accurately compared to the manual management of the garbage collector.
This means that the `timeit` module allows to reduce more noise than only the noise caused by the garbage collector, and thus is a much better approach to perform the timing measurements for the attack compared to the manual management of the source of noise.
That's why I used the `timeit` module for the timing measurements in the attack implementation instead of manually disabling the garbage collector.

```python
%| echo: false
%| raw: false
%| grid-inset: 6pt
%| label: fig1


import gc
import time

def get_samples_stats_manual(
    RSA_instance: RSA,
    d_A: int,
    num_samples: int = 10000,
    disable_gc: bool = True,
    warmup_reps: int = 0,
    progress_bar: bool = True,
) -> np.ndarray:
    """
    Collect decryption times for a fixed ciphertext.

    Parameters
    ----------
    RSA_instance : RSA
    d_A : int
        Private key.
    num_samples : int
    disable_gc : bool
        Disable GC during measurement (default: True).
    warmup_reps : int
        Warm-up iterations before measurement (0 = no warm-up).
    progress_bar : bool
        Show progress bar during measurement (default: True).
    Returns
    -------
    np.ndarray  shape (num_samples,), times in nanoseconds.
    """
    if disable_gc:
        gc.disable()
        gc.collect()

    # Localize hot references
    decrypt_fn = RSA_instance.decrypt
    perf_ns    = time.perf_counter_ns

    # Warm-up
    for _ in tqdm(range(warmup_reps), desc="Warm-up", disable=not progress_bar, leave=False):
        decrypt_fn(d_A)

    # Pre-allocated buffer
    samples = np.empty(num_samples, dtype=np.int64)
    for i in tqdm(range(num_samples), desc="Sampling", disable=not progress_bar, leave=False):
        t0 = perf_ns()
        decrypt_fn(d_A)
        samples[i] = perf_ns() - t0

    if disable_gc:
        gc.enable()

    return samples

samples_stats_0_manual = get_samples_stats_manual(RSA_instance, 0, num_samples=1000, disable_gc=True, warmup_reps=0, progress_bar=False)
samples_stats_1_timeit = get_samples_stats(RSA_instance, 0, num_samples=1000, warmup_reps=0, progress_bar=False)

plt.figure(figsize=(12, 6))
plt.suptitle("Comparison of timing measurements with manual garbage collector (GC) disable versus using timeit (GC handled automatically)")
plt.subplot(1, 2, 1)
plt.hist(samples_stats_0_manual, bins=200)
plt.title("Manual GC disable")
plt.xlabel("Decryption Time (ns)")
plt.ylabel("Frequency")
plt.subplot(1, 2, 2)
plt.hist(samples_stats_1_timeit, bins=200)
plt.title("Using timeit")
plt.xlabel("Decryption Time (ns)")
plt.ylabel("Frequency")
plt.tight_layout()
plt.show()
```


===== Averaging timing measurements

Once the garbage collector is disabled, there are still other sources of noise that can affect the timing measurements, as described in @noise.

The most common approach to try to extract the signal from the noise in timing measurements is to perform a large number of timing measurements and then average them.
Indeed, by performing a large number of timing measurements and then averaging them, we can reduce the impact of random fluctuations in the timing measurements.

However, as shown on @fig1, there are some samples for which the timing measurements are significantly higher than the others due to the sources of noise described in @noise, which can skew the average and thus make it not representative of the true decryption time.

To solve this problem, the first idea was to remove the outliers from the timing measurements by filtering out the timing measurements that are too far from the center of the distribution, such as bellow 25% and above 75%, which can help to reduce the impact of outliers on the analysis of the timing measurements by keeping only the most representative samples.

But is the averaging of the timing measurements sufficient to extract the signal from the noise and thus distinguish between the case with the extra multiplication (key 1) and the case without the extra multiplication (key 0) ?
Of course, not.
It was my first approach to try reducing the impact of noise, but it was not sufficient to extract the signal from the noise and thus distinguish between the two cases.
Indeed, when I was using a manual approach to disable the garbage collector, I was not able to distinguish between the two cases even after removing the outliers from the timing measurements, which can be explained by the fact that there are still other sources of noise that can affect the timing measurements, making the averaging of the timing measurements not sufficient to extract the signal from the noise.

In fact, the noise in the timing measurements is an additive noise, meaning that it can only add latency to the timing measurements, but it can never subtract latency from the timing measurements.
This means that the minimum timing measurement is the best estimator of the true decryption time, as the minimum timing measurement is the one that is least affected by the noise, while the other timing measurements can be significantly affected by the noise and thus can be much higher than the true decryption time.
So contrary to the average that can be skewed by outliers, the minimum timing measurement is the right approach to extract the signal from the noise.

===== Warm-up and optimizations of parameters

To reduce the impact of noise caused by the CPU cache effects and branch prediction, a warm-up phase was added before the timing measurements.

The warm-up phase consists in performing a certain number of decryption operations before the timing measurements.
This allows the CPU to load the relevant data and instructions into the cache and the branch predictor to learn the execution patterns of the algorithm, which can help to reduce the impact of noise caused by these factors and thus increase the chances of success of the attack.

However, by looking at the results with and without the warm-up phase in @fig2, we can see that the warm-up phase does not have a significant impact on the timing measurements, and thus does not help to reduce the impact of noise caused by the CPU cache effects and branch prediction.
Perhaps that the `timeit` module already handles some of the optimizations that can be achieved with a warm-up phase, such as loading the relevant data and instructions into the cache and learning the execution patterns of the algorithm, which can explain why the warm-up phase does not have a significant impact on the timing measurements.

So the attack will be implemented without a warm-up phase, as it does not seem to have a significant impact on the timing measurements and thus does not help to reduce the impact of noise caused by the CPU cache effects and branch prediction.
This allows to reduce the time taken for the attack, as the warm-up phase can be quite time-consuming, especially if we want to perform a large number of repetitions of the timing measurements.

```python
%| timeout: 3600
%| echo: false
%| raw: false
%| grid-inset: 6pt
%| label: fig2

big_key = d_A & ((1 << 1000) - 1)
h0_big_key = big_key
h1_big_key = big_key | (1 << 1000)

samples_stats_0_warmup = []
samples_stats_1_warmup = []
samples_stats_0_no_warmup = []
samples_stats_1_no_warmup = []

samples_stats_0_warmup_big_key = []
samples_stats_1_warmup_big_key = []
samples_stats_0_no_warmup_big_key = []
samples_stats_1_no_warmup_big_key = []

for _ in range(20):
    samples_stats_0_warmup.append(np.min(get_samples_stats(RSA_instance, 0, num_samples=1000, warmup_reps=200, progress_bar=False)))
    samples_stats_1_warmup.append(np.min(get_samples_stats(RSA_instance, 1, num_samples=1000, warmup_reps=200, progress_bar=False)))
    samples_stats_0_no_warmup.append(np.min(get_samples_stats(RSA_instance, 0, num_samples=1000, warmup_reps=0, progress_bar=False)))
    samples_stats_1_no_warmup.append(np.min(get_samples_stats(RSA_instance, 1, num_samples=1000, warmup_reps=0, progress_bar=False)))

    samples_stats_0_warmup_big_key.append(np.min(get_samples_stats(RSA_instance, h0_big_key, num_samples=1000, warmup_reps=200, progress_bar=False)))
    samples_stats_1_warmup_big_key.append(np.min(get_samples_stats(RSA_instance, h1_big_key, num_samples=1000, warmup_reps=200, progress_bar=False)))
    samples_stats_0_no_warmup_big_key.append(np.min(get_samples_stats(RSA_instance, h0_big_key, num_samples=1000, warmup_reps=0, progress_bar=False)))
    samples_stats_1_no_warmup_big_key.append(np.min(get_samples_stats(RSA_instance, h1_big_key, num_samples=1000, warmup_reps=0, progress_bar=False)))

plt.figure(figsize=(12, 10))
plt.suptitle("Comparison of differences with (h1) and without (h0) extra multiplications with and without warm-up phase with minimum timing measurements for small and big key sizes")
plt.subplot(2, 1, 1)
plt.title("Small key size")
plt.plot(samples_stats_0_warmup, label="h0 with warm-up")
plt.plot(samples_stats_1_warmup, label="h1 with warm-up")
plt.plot(samples_stats_0_no_warmup, label="h0 without warm-up")
plt.plot(samples_stats_1_no_warmup, label="h1 without warm-up")
plt.xlabel("Number of repetitions")
plt.ylabel("Decryption Time (ns)")
plt.legend()
plt.subplot(2, 1, 2)
plt.title("Big key size")
plt.plot(samples_stats_0_warmup_big_key, label="h0 with warm-up")
plt.plot(samples_stats_1_warmup_big_key, label="h1 with warm-up")
plt.plot(samples_stats_0_no_warmup_big_key, label="h0 without warm-up")
plt.plot(samples_stats_1_no_warmup_big_key, label="h1 without warm-up")
plt.xlabel("Number of repetitions")
plt.ylabel("Decryption Time (ns)")
plt.legend()
plt.tight_layout()
plt.show()
```

If we look at the results obtained with the big key size, we can see that it starts to be more difficult to distinguish between the two cases with and without the extra multiplication, which can be explained by the fact that the timing variations caused by the square-and-multiply algorithm are smaller for larger key sizes, making it more difficult to extract the signal from the noise and thus distinguish between the two cases.
This can be problematic for the attack, as it relies on the ability to distinguish between the two cases with and without the extra multiplication to recover the bits of the private key $d$.

So I tried in @fig3 to analyze the minimum repetitions needed to start to be able to distinguish between the two cases with and without the extra multiplication for a big key size, by plotting the minimum decryption time obtained for both cases with different numbers of repetitions of timing measurements.
Each measurement is repeated 10 times to try to reduce the impact of noise, allowing to better visualize if the two cases are distinguishable or not.

The results show that for a big key size, it starts to be possible to distinguish between the two cases when we perform around 10000 repetitions of timing measurements, which can be quite time-consuming...



```python
%| timeout: 3600
%| echo: false
%| raw: false
%| grid-inset: 6pt
%| label: fig3


def plot_repetition_convergence(
    RSA_instance: RSA,
    d_h0: int,
    d_h1: int,
    sample_counts: list = [1, 10, 100, 500, 1000, 2000, 5000],
    n_runs: int = 10,
):
    h0_means = []
    h1_means = []

    for n in sample_counts:
        tmp_h0 = []
        tmp_h1 = []
        for _ in range(n_runs):
            tmp_h0.append(np.min(get_samples_stats(RSA_instance, d_h0, num_samples=n, warmup_reps=0)))
            tmp_h1.append(np.min(get_samples_stats(RSA_instance, d_h1, num_samples=n, warmup_reps=0)))
        h0_means.append(np.mean(tmp_h0))
        h1_means.append(np.mean(tmp_h1))

    plt.figure(figsize=(6, 6))
    plt.plot(sample_counts, h0_means, label='h0')
    plt.plot(sample_counts, h1_means, label='h1')
    plt.xscale('log')
    plt.xlabel('Number of samples')
    plt.ylabel('Minimum decryption time (ns)')
    plt.title('Convergence of minimum decryption time with number of samples')
    plt.legend()

    plt.tight_layout()
    plt.show()

big_key = d_A & ((1 << 1000) - 1)
h0_big_key = big_key
h1_big_key = big_key | (1 << 1000)

plot_repetition_convergence(RSA_instance, h0_big_key, h1_big_key, sample_counts=[1, 10, 100, 500, 1000, 2000, 3000, 5000, 7000, 10000], n_runs=10)
```

==== Performance of the attack

I first tried to implement the attack in Python with a simple version that does not look after noise, but it was not successful at all in recovering the private key due to the high noise caused by the Python interpreter and its optimizations, which totally masked the timing variations caused by the square-and-multiply algorithm.
Indeed, the error rate was at best around 50%, meaning that the attack was not able to distinguish between the two cases and make only random guesses for the bits of the private key $d$.

Then, I implemented a version that uses repeated timing measurements and that looks after the garbage collector, but it was still not successful at all in recovering the private key.
This is perhaps due to the fact that I was using the average of the timing measurements instead of the minimum.
Note that I thought to remove the outliers from the timing measurements to try to reduce the impact of noise, but it was not sufficient to extract the signal from the noise.

Finally, I tried to implement the attack in Python with the improvements described above, and I run it for 13 hours to try to recover the private key $d$ with a key size of 1024 bits.
I only managed to recover 5 bits of the private key $d$ using 1000 messages and 10000 repetitions of timing measurements for each message.
And I have assumed that the first 16 bits of the private key $d$ are known.
I use 3 candidates per iteration to try to reduce the impact of errors in the previous bits on the variance and thus reduce the number of errors in the recovered private key.

On the obtained results, we can see that one of the candidates has an error rate of 0%, meaning that it is the correct private key, while the other candidates have an error rate of 20%, meaning that they have some errors in the recovered bits of the private key.
This means that the attack was successful in recovering some bits of the private key.
But due to the computational cost of the attack, I was not able to recover more than 5 bits of the private key $d$ in a reasonable time.

```raw
Iteration 1/5: bit guessed = 1  (var h0 = 1.5563e+08, var h1 = 1.5628e+08)  ✗ WRONG
                                                   
Iteration 2/5: bit guessed = 1  (var h0 = 1.5586e+08, var h1 = 1.5514e+08)  ✓ CORRECT
                                                   
Iteration 3/5: bit guessed = 1  (var h0 = 1.5520e+08, var h1 = 1.5653e+08)  ✓ CORRECT
                                                   
Iteration 4/5: bit guessed = 0  (var h0 = 1.5497e+08, var h1 = 1.5614e+08)  ✓ CORRECT
                                                   
Iteration 5/5: bit guessed = 1  (var h0 = 1.5522e+08, var h1 = 1.5507e+08)  ✓ CORRECT

────────────────────────────────────────
Candidate #1
  Key:        1234141
  Variance:   1.5475e+08
  Error rate: 20.00%  (1/5 bits wrong)
────────────────────────────────────────
Candidate #2
  Key:        1496285
  Variance:   1.5507e+08
  Error rate: 0.00%  (0/5 bits wrong)
────────────────────────────────────────
Candidate #3
  Key:        447709
  Variance:   1.5522e+08
  Error rate: 20.00%  (1/5 bits wrong)
────────────────────────────────────────
```

== Pearson-based timing attack

To exploit more efficiently the timing variations in the square-and-multiply algorithm, it is possible to use the Pearson correlation coefficient instead of the variance to determine which guess for the bit of the private key $d$ is more likely to be correct.

=== Pearson correlation coefficient

The Pearson correlation coefficient is a measure of the linear correlation between two variables, in this case, the timing measurements and the expected timings based on the guess for the bit of the private key $d$.

The Pearson correlation coefficient can be formally defined as:

#let Cov = math.op("Cov")
#let Var = math.op("Var")

$ r = Cov(T, t(C, x_b))/(sigma_T sigma_(t(C, x_b))) $

with:
- $r$ the Pearson correlation coefficient.
- $C$ the set of ciphertexts $C = {c_1, c_2, ..., c_n}$.
- $T$ the vector of timing measurements obtained from the server for the set of ciphertexts $C$.
- $t(C, x_b)$ the vector of expected timings based on the guess $x_b$ for the bit of the private key $d$ for the set of ciphertexts $C$.
- $sigma_T$ the standard deviation of the timing measurements $T$.
- $sigma_(t(C, x_b))$ the standard deviation of the expected timings $t(C, x_b)$.

A value close to 1 indicates a strong positive correlation, meaning that the timing measurements and the expected timings are closely related
A value close to -1 indicates a strong negative correlation, and a value close to 0 indicates no linear correlation.

As we want that our guess for the bit of the private key $d$ explains the timing variations in the square-and-multiply algorithm, we want to maximize the Pearson correlation between the timing measurements and the expected timings.

Depending on the model of the expected timings based on the guess for the bit of the private key $d$, it is possible to have a positive or negative correlation between the timing measurements and the expected timings, meaning that the model of the expected timings is inverted compared to the timing measurements.

So we are more interested in the strength of the correlation rather than its sign, meaning that we want to maximize the absolute value of the Pearson correlation coefficient between the timing measurements and the expected timings.

=== Designing the model of expected timings

The idea is to create a function $t(C, x_b)$ that estimates the expected timings based on the guess $x_b$ and the set of ciphertexts $C$.
Indeed, the model must take into account the size of the ciphertexts that lead to different timings for the decryption operation, as well as the guess for the bit of the private key $d$ that leads to different execution paths in the square-and-multiply algorithm and thus different timings.

A simple approach can consist to use the Hamming weight of the intermediate values in the square-and-multiply algorithm as a model for the expected timings.
The Hamming weight of a binary number is the number of bits that are set to 1 in the binary representation of the number.
It can be used to estimate the complexity of the operations, as the operations that involve more bits set to 1 can be more complex and thus take more time to execute.

The cost computation for the square-and-multiply algorithm can be modeled as follows:

```python
%| execute: false
def square_and_multiply_with_cost(y, x, n, t_mul=1.1):
    """
    Square-and-multiply algorithm with cost modeling.
     - t_mul: cost factor for multiplication operations
     - t_square: cost factor for squaring operations
    """
    s = 1
    y %= n
    cost = 0

    while x > 0:
        if x & 1:
            s = (s * y) % n
            cost += t_mul * s.bit_count()
        y = (y * y) % n
        x >>= 1
    return s, cost
```

Note that we increase the cost only for the extra multiplication operations, as the squaring operations are performed in both cases with and without the extra multiplication, meaning that they do not contribute to the timing variations that we want to exploit for the attack.

=== Advantages of the Pearson-based approach

Compared to the variance based approach, the Pearson correlation coefficient can be more efficient to determine which guess for the bit of the private key $d$ is more likely to be correct, as it takes into account the relationship between the timing measurements and the expected timings based on the guess for the bit of the private key $d$, rather than just looking at the variance of the timing measurements for each guess.

Indeed, Pearson based approach aims to explain the variations in the execution time of the square-and-multiply algorithm using a simple model that is independent of noise, machine architecture, algorithm implementation, the chosen programming language, and so on.

In this way, the attack depends only on the ability to capture the timing variations from a server.

On top of that, the Pearson approach allows to avoid performing a large number of timing measurements for each guess, allowing to significantly reduce the time taken for the attack.

For instance, instead of performing 1000 messages $dot$ 10000 repetitions = 10 million timing measurements for each guess for the bit of the private key $d$, we only need to compute the Pearson correlation coefficient between two vectors of size 1000, which can be done in a reasonable time even for a large key size.

=== Disadvantages of the Pearson-based approach

The main disadvantage of the Pearson-based approach is that it relies on the design of a good model for the expected timings based on the guess for the bit of the private key $d$.

If the model is not well designed, it can lead to a low Pearson correlation coefficient even for the correct guess for the bit of the private key $d$, making it difficult to distinguish between the correct and incorrect guesses.
And if the model is too complex, the computation of the expected timings can be time-consuming, which can increase the time taken for the attack.

=== Results of the Pearson-based approach

The results of the Pearson-based approach are quite good, as the second candidate has no error like for the variance-based approach.

```raw
Iteration 1/5: bit guessed = 0  (r h0 = -0.0077, r h1 = -0.0238)  ✓ CORRECT
Iteration 2/5: bit guessed = 0  (r h0 = -0.0233, r h1 = -0.0185)  ✗ WRONG
Iteration 3/5: bit guessed = 1  (r h0 = -0.0216, r h1 = -0.0178)  ✓ CORRECT
Iteration 4/5: bit guessed = 0  (r h0 = -0.0055, r h1 = -0.0056)  ✓ CORRECT
Iteration 5/5: bit guessed = 1  (r h0 = -0.0024, r h1 = +0.0144)  ✓ CORRECT

────────────────────────────────────────
Candidate #1
  Key:        2020573
  Pearson r:  +0.0144
  Error rate: 20.00%  (1/5 bits wrong)
────────────────────────────────────────
Candidate #2
  Key:        1496285
  Pearson r:  +0.0087
  Error rate: 0.00%  (0/5 bits wrong)
────────────────────────────────────────
Candidate #3
  Key:        316637
  Pearson r:  -0.0003
  Error rate: 40.00%  (2/5 bits wrong)
────────────────────────────────────────
```

However, compared to the variance-based approach, only 2000 repetitions of timing measurements were used, and the attack was achieved in around 2 hours, which is significantly faster than the 13 hours taken for the variance-based approach.

We can constate that the Pearson correlation coefficient (Pearson r) is very close to 0 for all candidates, even for the correct candidate, which can be explained by the fact that the model for the expected timings is not perfect and thus does not explain well the timing variations in the square-and-multiply algorithm, or perhaps that the timing variations in the square-and-multiply algorithm don't vary so much.

To improve the Pearson-based approach, it would be interesting to try to design a better model for the expected timings based on the guess for the bit of the private key $d$, which can help to increase the Pearson correlation coefficient for the correct guess and thus make it easier to distinguish between the correct and incorrect guesses.
Or it would be interesting to try to collect more timing measurements from the server to have more chance to capture the true timing variations.

A test to recover 10 bits was done, and the results are not so good because the error rate of the three first candidates is around 40%, meaning that they have some errors in the recovered bits of the private key, while the two last candidates have an error rate of 30%, meaning that they have some errors in the recovered bits of the private key but less than the three first candidates.

An error rate of 40% is almost random guessing, meaning that the attack is not able to distinguish between the correct and incorrect guesses for the bits of the private key $d$, while an error rate of 30% is better than random guessing.

```raw
Iteration  1/10: bit guessed = 1  (r h0 = +0.0000, r h1 = +0.0461)  ✓ CORRECT
Iteration  2/10: bit guessed = 0  (r h0 = +0.0461, r h1 = +0.0429)  ✓ CORRECT
Iteration  3/10: bit guessed = 1  (r h0 = +0.0429, r h1 = +0.0704)  ✓ CORRECT
Iteration  4/10: bit guessed = 0  (r h0 = +0.0704, r h1 = +0.0512)  ✗ WRONG
Iteration  5/10: bit guessed = 1  (r h0 = +0.0512, r h1 = +0.0461)  ✓ CORRECT
Iteration  6/10: bit guessed = 1  (r h0 = +0.0626, r h1 = +0.0657)  ✗ WRONG
Iteration  7/10: bit guessed = 0  (r h0 = +0.0657, r h1 = +0.0756)  ✗ WRONG
Iteration  8/10: bit guessed = 1  (r h0 = +0.0756, r h1 = +0.0687)  ✓ CORRECT
Iteration  9/10: bit guessed = 1  (r h0 = +0.0930, r h1 = +0.0880)  ✗ WRONG
Iteration 10/10: bit guessed = 0  (r h0 = +0.0880, r h1 = +0.0782)  ✓ CORRECT

────────────────────────────────────────
Candidate #1
  Key:        407
  Pearson r:  +0.1067
  Error rate: 40.00%  (4/10 bits wrong)
────────────────────────────────────────
Candidate #2
  Key:        663
  Pearson r:  +0.0962
  Error rate: 40.00%  (4/10 bits wrong)
────────────────────────────────────────
Candidate #3
  Key:        919
  Pearson r:  +0.0956
  Error rate: 50.00%  (5/10 bits wrong)
────────────────────────────────────────
Candidate #4
  Key:        247
  Pearson r:  +0.0930
  Error rate: 30.00%  (3/10 bits wrong)
────────────────────────────────────────
Candidate #5
  Key:        151
  Pearson r:  +0.0904
  Error rate: 30.00%  (3/10 bits wrong)
────────────────────────────────────────
```

=== Why the timing attack on RSA is still relevant

Even if the timing attack on RSA is not as efficient as I expected, it is still relevant to study it and try to implement it, as it allows to understand the vulnerabilities of RSA and the importance of implementing countermeasures against timing attacks.
Indeed, the timing attack on RSA is a well-known attack that can be used to recover the private key $d$ by exploiting the timing variations in the square-and-multiply algorithm, and it has been shown to be effective in certain scenarios, such as when the implementation of RSA is not properly protected against timing attacks.

In general, servers are set up one time for many years, and they are optimized as much as the actual modern CPU architecture allows.
On top of that, the implementations on a server are often done in low-level programming languages such as C or Rust, which can allow to reduce the noise in the timing measurements and thus increase the chances of success of the attack compared to high-level programming languages such as Python.

In this way, the timing variations caused by the square-and-multiply algorithm running on a server can be more significant and thus easier to exploit for the attack compared to the timing variations caused by the square-and-multiply algorithm running on a local machine with a high optimized setup.

#pagebreak()

= Fermat's factorization method on RSA

== Security of RSA and factoring large integers

The private key $d$ in RSA is computed based on the prime factors $p$ and $q$ of the modulus $n$.
So another way to recover the private key $d$ is to factor the modulus $n$ into its prime factors $p$ and $q$, and then compute $d$ using the formula $d equiv e^(-1) mod phi(n)$ with $phi(n) = (p - 1)(q - 1)$ the Euler's totient function.
The inverse of $e$ modulo $phi(n)$ can be computed using the Extended Euclidean Algorithm, which is an efficient method for computing the greatest common divisor of two integers and their multiplicative inverse.

But factoring large integers is a computationally hard problem, and the security of RSA relies on this fact.

However, if $p$ and $q$ are close to each other, meaning that the difference between $p$ and $q$ is small, then it becomes easy to factor $n$ using Fermat's factorization method, as described by Hanno Böck in his paper "Fermat Factorization in the Wild" @fermat.

This paper is quite recent (2023) and it shows that there are still some implementations of RSA that are vulnerable to Fermat's factorization method due to the fact that they use prime numbers $p$ and $q$ that are close to each other, which can be explained by the fact that it is easier to generate prime numbers that are close to each other compared to generating prime numbers that are far from each other.

That's why it is important to study Fermat's factorization method and try to implement it, as it allows to understand the vulnerabilities of RSA and the importance of generating prime numbers that are not close to each other to ensure the security of RSA.

== Description of Fermat's factorization method <theory>

Fermat's factorization method relies on the fact that $n$ is a product of two odd primes $p$ and $q$.
As $p$ and $q$ are odd, there always exist an integer number which is at the middle of $p$ and $q$, which is $x = (p + q)/2$.
Then, we consider $y$ as the distance between $x$ and $p$ (or $q$):
$ y = x - p = q - x $

So we have:
- $p = x - y$
- $q = x + y$

If we express $n$ in terms of $x$ and $y$, we get:
$ n = p times q = (x - y)(x + y) = x^2 - y^2 $

From this equation, we can deduce that $y^2 = x^2 - n$.

== From theory to the algorithm

The Fermat's factorization method consists in finding the smallest integer $x$ such that $y^2 = x^2 - n$ is a perfect square, meaning that $y$ is an integer.

Once we find such an integer $x$, we can compute $y$ as $y = sqrt(x^2 - n)$, and then we can obtain the prime factors $p$ and $q$ as described in @theory.

So the algorithm can be summarized as follows:

1. Compute $x = ceil(sqrt(n))$.
2. Compute $y^2 = x^2 - n$.
3. If $y^2$ is a perfect square, then $y = sqrt(y^2)$ and we can compute $p = x - y$ and $q = x + y$.
4. Otherwise, increment $x$ and repeat from step 2.