// Main report file
#import "template.typ": make-report, report-footnote
#import "metadata.typ": my-report
#import "@preview/cetz:0.3.1": canvas, draw, tree

// Main content
#show: make-report.with(my-report)
#show raw.where(block: true): set block(fill: luma(240), inset: 1em, radius: 0.5em, width: 100%)
#show raw.where(block: false): box.with(
  fill: rgb("#e573e927"),
  inset: (x: 3pt, y: 0pt),
  outset: (y: 3pt),
  radius: 2pt,
)

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
import random
import time
import numpy as np
from tqdm import tqdm, trange
from alive_progress import alive_bar, alive_it
import matplotlib.pyplot as plt
import gc
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

def remove_outliers(samples, percentile=0.25):
    samples = np.asarray(samples)
    
    if percentile >= 1:
        percentile /= 100
    
    down = np.percentile(samples, percentile * 100)
    up = np.percentile(samples, (1 - percentile) * 100)
    
    return samples[(samples >= down) & (samples <= up)]

def collect_samples(
    RSA_instance: RSA,
    num_samples: int = 1000,
    num_repetitions: int = 10000,
    private_key: int = None,
    progress_bar: bool = True,
    disable_gc: bool = True,
    warmup_reps: int = 200,
) -> np.ndarray:
    """Collect timing samples for RSA decryption.

    Parameters
    ----------
    RSA_instance : RSA
        An instance of the RSA class.
    num_samples : int
        The number of timing samples to collect.
    num_repetitions : int
        The number of times to repeat each decryption operation.
    private_key : int, optional
        The private key to use for decryption. If not provided, the instance's private key will be used.
    progress_bar : bool, default=True
        Whether to display a progress bar.
    disable_gc : bool, default=True
        Whether to disable garbage collection during timing measurements.
    warmup_reps : int, default=200
        The number of warm-up repetitions.

    Returns
    -------
    np.ndarray
        An array of timing samples.
    """

    key = private_key if private_key is not None else RSA_instance.private_key

    # Deactivate GC and collect garbage to minimize its impact on timing measurements
    if disable_gc:
        gc.disable()
        gc.collect()

    # Locate hot references
    decrypt_fn = RSA_instance.decrypt
    perf_ns    = time.perf_counter_ns
    n          = RSA_instance.n

    # Warm-up (stabilize branch predictor + CPU caches)
    for _ in range(warmup_reps):
        decrypt_fn(random.randint(1, n - 1), private_key=key)

    # Buffer pre-allocated (zero allocation in inner loop)
    timing_buf = np.empty(num_repetitions, dtype=np.int64)
    samples    = np.empty((num_samples, 2), dtype=np.float64)

    for i in tqdm(range(num_samples), disable=not progress_bar, leave=False):
        cipher = random.randint(1, n - 1)

        for j in range(num_repetitions):
            t0 = perf_ns()
            decrypt_fn(cipher, private_key=key)
            timing_buf[j] = perf_ns() - t0

        samples[i] = [cipher, remove_outliers(timing_buf).mean()]

    if disable_gc:
        gc.enable()
    return samples

def timing_attack(RSA_instance: RSA, num_samples: int = 1000, num_repetitions: int = 1, num_iterations: int = 10, num_known_bits: int = 5, buffer_size: int = 5, disable_gc: bool = True, warmup_reps: int = 10, progress_bar: bool = False) -> int:
    """
    Perform a timing attack on the RSA instance to recover the private key.

    Parameters
    ----------
    RSA_instance : RSA
        An instance of the RSA class.
    num_samples : int
        Number of samples to collect for the attack.
    num_repetitions : int
        Number of times to repeat each measurement.
    num_iterations : int
        Number of iterations to perform.
    num_known_bits : int
        Number of known bits of the private key.
    buffer_size : int
        The size of the buffer for the beam search.
    disable_gc : bool
        Whether to disable garbage collection during timing measurements.
    warmup_reps : int
        Number of warm-up repetitions to perform before collecting samples.
    progress_bar : bool
        Whether to display a progress bar during sample collection.

    Returns
    -------
    int
        The recovered private key.
    """
    server_samples = collect_samples(RSA_instance, num_samples, num_repetitions, disable_gc=disable_gc, warmup_reps=warmup_reps, progress_bar=progress_bar)
    initial_key = RSA_instance.private_key & ((1 << num_known_bits) - 1)

    # buffer of candidate keys
    candidate_keys = np.full(buffer_size, initial_key)

    # variance associated with each key
    candidate_variances = np.full(buffer_size, np.inf)

    # historical data
    history_keys = np.zeros((num_iterations, buffer_size))
    history_variances = np.zeros((num_iterations, buffer_size))

    error_rate = 0

    for i in range(num_iterations):

        tested_keys = []
        tested_variances = []

        # We test 2 hypotheses for each key in the buffer
        for key in candidate_keys:

            key_h0 = key
            key_h1 = key | (1 << (num_known_bits + i))

            h0_samples = collect_samples(RSA_instance, num_samples, num_repetitions, private_key=key_h0, disable_gc=disable_gc, warmup_reps=warmup_reps, progress_bar=progress_bar)
            h0_variance = np.var(server_samples[:, 1] - h0_samples[:, 1])

            tested_keys.append(key_h0)
            tested_variances.append(h0_variance)

            h1_samples = collect_samples(RSA_instance, num_samples, num_repetitions, private_key=key_h1, disable_gc=disable_gc, warmup_reps=warmup_reps, progress_bar=progress_bar)
            h1_variance = np.var(server_samples[:, 1] - h1_samples[:, 1])

            tested_keys.append(key_h1)
            tested_variances.append(h1_variance)

        tested_keys = np.array(tested_keys)
        tested_variances = np.array(tested_variances)

        # We keep the best buffer_size hypotheses
        best_indices = np.argsort(tested_variances)[:buffer_size]

        candidate_keys = tested_keys[best_indices]
        candidate_variances = tested_variances[best_indices]

        # Update historical data
        history_keys[i] = candidate_keys
        history_variances[i] = candidate_variances

        # debug : best key in the buffer and its associated bit
        best_key = candidate_keys[0]
        bit_guessed = (best_key >> (num_known_bits + i)) & 1
        bit_private_key = (RSA_instance.private_key >> (num_known_bits + i)) & 1

        print(f"Iteration {i + 1}/{num_iterations}: bit guessed {bit_guessed} (h0 variance = {h0_variance}, h1 variance = {h1_variance}) {'✓ CORRECT' if bit_guessed == bit_private_key else '✗ WRONG'}")

    # Compute error rate for each candidate key in the buffer
    error_rate = []
    for key, variance in zip(candidate_keys, candidate_variances):
        guessed_key = (key >> num_known_bits) % (1 << num_iterations)
        real_key = (RSA_instance.private_key >> num_known_bits) % (1 << num_iterations)
        errors = (guessed_key ^ real_key).bit_count()
        error_rate.append(errors / num_iterations * 100)
        print("\n" + "-" * 30)
        print(f"Candidate key:  {key}")
        print(f"Variance:       {variance}")
        print(f"Error rate:     {error_rate[-1]:.2f}%")
        print("-" * 30)
    return candidate_keys, error_rate

def get_samples_stats(
    RSA_instance: RSA,
    d_A: int,
    num_samples: int = 10000,
    disable_gc: bool = False,
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
        Disable GC during measurement (default: False).
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

def plot_distributions(samples_stats_h0: np.ndarray, samples_stats_h1: np.ndarray, percentile=25, title: str = "Distribution of decryption times for two hypotheses with branch prediction"):
    plt.figure(figsize=(12, 8))
    plt.suptitle(title)
    plt.subplot(2, 2, 1)
    plt.hist(samples_stats_h0, bins=200)
    plt.axvline(np.mean(samples_stats_h0), color='red', linestyle='dashed', linewidth=1, label=f'Mean: {np.mean(samples_stats_h0):.4f} ms')
    plt.title("Hypothesis h0: the last bit is 0")
    plt.xlabel("Decryption Time")
    plt.ylabel("Frequency")
    plt.legend()
    plt.subplot(2, 2, 2)
    plt.hist(samples_stats_h1, bins=200)
    plt.axvline(np.mean(samples_stats_h1), color='red', linestyle='dashed', linewidth=1, label=f'Mean: {np.mean(samples_stats_h1):.4f} ms')
    plt.title("Hypothesis h1: the last bit is 1")
    plt.xlabel("Decryption Time")
    plt.ylabel("Frequency")
    plt.legend()
    plt.subplot(2, 2, 3)
    plt.hist(remove_outliers(samples_stats_h0, percentile=percentile), bins=50)
    plt.axvline(np.mean(remove_outliers(samples_stats_h0, percentile=percentile)), color='red', linestyle='dashed', linewidth=1, label=f'Mean: {np.mean(remove_outliers(samples_stats_h0, percentile=percentile)):.4f} ms')
    plt.title("Hypothesis h0: the last bit is 0 (without outliers)")
    plt.xlabel("Decryption Time")
    plt.ylabel("Frequency")
    plt.legend()
    plt.subplot(2, 2, 4)
    plt.hist(remove_outliers(samples_stats_h1, percentile=percentile), bins=50)
    plt.axvline(np.mean(remove_outliers(samples_stats_h1, percentile=percentile)), color='red', linestyle='dashed', linewidth=1, label=f'Mean: {np.mean(remove_outliers(samples_stats_h1, percentile=percentile)):.4f} ms')
    plt.title("Hypothesis h1: the last bit is 1 (without outliers)")
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


== Timing attacks on RSA

Before the exchange of symmetric keys, the client and the server need to perform an RSA encryption and decryption operation to establish a secure communication channel.
The timing of these operations can be exploited by attackers to infer information about the private key.

As mentioned earlier, the security of RSA relies on the difficulty of factoring large integers, but the implementation of RSA can introduce vulnerabilities that can be exploited by attackers.
The goal of the attacker is to recover the unknown private key $d$ thanks to the knowledge of the public key $(n, e)$ and the ability to perform encryption and decryption operations on the server using the RSA algorithm.

== Square-and-multiply algorithm

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

== Exploiting timing variations

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

== Code implementation

The code implementation was done first in Python, and then in Rust and C++ to try to reduce the noise in the timing measurements and thus increase the chances of success of the attack.

Indeed, the python implementation was not successful at all in recovering the private key due to the high noise caused by the Python interpreter and its optimizations, which totally masked the timing variations caused by the square-and-multiply algorithm.

=== Sources of noise <noise>

There are several sources of noise that can affect the timing measurements in programming languages, especially in high-level languages like Python.

==== CPU cache effects

CPU cache effects that can cause variability in the timing measurements based on the memory access patterns of the algorithm.

First, there are different levels of CPU cache (L1, L2, L3) that can store recently accessed data and instructions.

These caches are designed to speed up access to frequently used data and instructions, but they can also introduce variability in the timing measurements.
Indeed, the cache L1 is the fastest but also the smallest, while the cache L3 is the slowest but also the largest, meaning that if the data or instructions needed for the algorithm are in the cache L1, the timing measurements will be faster compared to when they are in the cache L3 or not in the cache at all.

If the data or instructions needed are not in the cache, the CPU triggers a cache miss, which means that it has to fetch the data from the main memory, leading to a significant delay in the execution of the algorithm and thus in the timing measurements.

These cache effects represent a significant source of noise in timing measurements.

==== Branch prediction

Branch prediction is a technique used by modern CPUs to improve performance by guessing the outcome of conditional statements and executing instructions based on those guesses.
When the CPU encounters a conditional statement (e.g., an if statement), it makes a guess about which branch of the code will be executed next based on past behavior and patterns.
This allows the CPU to continue executing instructions without waiting for the outcome of the conditional statement, which can improve performance.

So if the CPU correctly predicts the branch, it can continue executing instructions without interruption, but if the CPU incorrectly predicts the branch, it has to discard the incorrectly executed instructions and fetch the correct instructions, leading to a significant delay in the execution of the algorithm and thus in the timing measurements.

That's why branch prediction can cause variability in the timing measurements based on the input values and the internal state of the algorithm, as different inputs can lead to different execution paths and thus different branch predictions.

==== Garbage collection

Garbage collection is a form of automatic memory management that is used in many programming languages, including Python.
It is responsible for automatically freeing up memory that is no longer in use by the program, which can help prevent memory leaks and improve performance.

However, the garbage collector can be triggered at any time during the execution of the program.
When the garbage collector runs, it can cause significant delays in the execution of the program: it has to pause the execution of the program, scan the memory for objects that are no longer in use, and free up the memory occupied by those objects.

This can lead to significant variability in the timing measurements since the garbage collector can be triggered at different times during the execution of the algorithm, leading to different timing measurements for the same operations.

==== Multiplication optimizations

The usage of modern programming languages introduces various optimizations that can affect the timing measurements, such as the optimization of multiplication operations.

The multiplication of large integers can be optimized using different algorithms depending on the size of the numbers.
For small integers, the standard multiplication algorithm is used whereas for larger integers, more efficient algorithms such as Karatsuba or Toom-Cook can be used.

These optimizations can lead to different timing measurements for the same operations based on the size of the numbers being multiplied.

==== Other optimizations

There are also other optimizations that can be introduced by the programming language or the compiler, such as loop unrolling, instruction reordering, or just-in-time compilation, which can further introduce variability in the timing measurements.

So the sources of noise in timing measurements can be quite significant, especially in high-level programming languages like Python, and they can totally mask the timing variations caused by the square-and-multiply algorithm.

=== Reducing the impact of noise

There are several techniques that can be used to try to reduce the impact of these sources of noise in timing measurements.

==== Averaging timing measurements

The first approach can consist to perform a large number of timing measurements for each sample and then use statistical analysis to try to extract the signal from the noise, such as computing the mean or the median of the timing measurements for each sample.

However, as shown on @fig1, there are some samples for which the timing measurements are significantly higher than the others, which can be caused by the garbage collector or other sources of noise described in @noise, and these outliers can significantly affect the mean and thus the analysis of the timing measurements.

Indeed, on the @fig1, we can see that the mean of the timing measurements of the key 0 is higher than the mean of the timing measurements of the key 1, which is not expected since the key 0 should be faster than the key 1 due to the extra multiplication performed when the bit of the key is 1.

```python
%| echo: false
%| raw: false
%| grid-inset: 6pt
%| label: fig1
%| plt-axes.grid: false

samples_stats_0 = get_samples_stats(RSA_instance, 0, num_samples=10000, disable_gc=False, warmup_reps=0, progress_bar=False) / 1e6
samples_stats_1 = get_samples_stats(RSA_instance, 1, num_samples=10000, disable_gc=False, warmup_reps=0, progress_bar=False) / 1e6

plt.figure(figsize=(12, 6))
plt.suptitle("10000 timing measurements of the decryption operation\non a single ciphertext for two different private keys (0 and 1)")
plt.subplot(1, 2, 1)
plt.hist(samples_stats_0, bins=1000)
plt.axvline(np.mean(samples_stats_0), color='red', linestyle='dashed', linewidth=1, label=f'Mean: {np.mean(samples_stats_0):.4f} ms')
plt.title("Key 0")
plt.xlabel("Decryption Time (ms)")
plt.ylabel("Frequency")
plt.legend()

plt.subplot(1, 2, 2)
plt.hist(samples_stats_1, bins=1000)
plt.axvline(np.mean(samples_stats_1), color='red', linestyle='dashed', linewidth=1, label=f'Mean: {np.mean(samples_stats_1):.4f} ms')
plt.title("Key 1")
plt.xlabel("Decryption Time (ms)")
plt.ylabel("Frequency")
plt.legend()

plt.tight_layout()
plt.show()
```

A way to mitigate the impact of these outliers is to filter them out by removing the timing measurements that are too far from the center of the distribution.
This can be done by removing the timing measurements that are bellow or above a certain percentile of the distribution, such as bellow 25% and above 75%, which can help to reduce the impact of outliers on the analysis of the timing measurements by keeping only the most representative samples.

However, as shown on @fig2, even after removing the outliers, the average timing measurements for the key 0 are still higher than the average timing measurements for the key 1, which is not expected since the key 0 should be faster than the key 1 due to the extra multiplication performed when the bit of the key is 1.

This can be explained by the fact that the sources of noise described in @noise are still present in the timing measurements, making the averaging of the timing measurements not sufficient to extract the signal from the noise.

```python
%| echo: false
%| raw: false
%| grid-inset: 6pt
%| label: fig2

plt.figure(figsize=(12, 6))
plt.suptitle("Removing outliers from the timing measurements\nby keeping only the samples between 25% and 75%")
plt.subplot(1, 2, 1)
plt.hist(remove_outliers(samples_stats_0, percentile=25), bins=100)
plt.axvline(np.mean(remove_outliers(samples_stats_0, percentile=25)), color='red', linestyle='dashed', linewidth=1, label=f'Mean: {np.mean(remove_outliers(samples_stats_0, percentile=25)):.4f} ms')
plt.title("Key 0")
plt.xlabel("Decryption Time (ms)")
plt.ylabel("Frequency")
plt.legend()
plt.subplot(1, 2, 2)
plt.hist(remove_outliers(samples_stats_1, percentile=25), bins=100)
plt.axvline(np.mean(remove_outliers(samples_stats_1, percentile=25)), color='red', linestyle='dashed', linewidth=1, label=f'Mean: {np.mean(remove_outliers(samples_stats_1, percentile=25)):.4f} ms')
plt.title("Key 1")
plt.xlabel("Decryption Time (ms)")
plt.ylabel("Frequency")
plt.legend()

plt.tight_layout()
plt.show()
```

==== Warm-up and disabling garbage collection

As making a large number of timing measurements is not sufficient to extract the signal from the noise, another approach can consist to try to reduce the sources of noise in the timing measurements.

As mentioned in @noise, the garbage collector is a significant source of noise in the timing measurements, so one way to reduce the noise is to disable the garbage collector during the timing measurements.

This can be done using the `gc` module in Python, which provides functions to enable and disable the garbage collector.

The obtained results shown on @fig3 are much better than the previous results shown on @fig1 and @fig2, as we can see that the average timing measurements for the key 0 are now lower than the average timing measurements for the key 1 as expected.

```python
%| echo: false
%| raw: false
%| grid-inset: 6pt
%| label: fig3

samples_stats_no_gc_0 = get_samples_stats(RSA_instance, 0, num_samples=10000, disable_gc=True, warmup_reps=0, progress_bar=False) / 1e6
samples_stats_no_gc_1 = get_samples_stats(RSA_instance, 1, num_samples=10000, disable_gc=True, warmup_reps=0, progress_bar=False) / 1e6

plot_distributions(samples_stats_no_gc_0, samples_stats_no_gc_1, percentile=25, title="Timing measurements with garbage collection disabled")
```

Now, the problem is that the two measurements for the key 0 and the key 1 are still quite close to each other.
To try to further reduce the noise in the timing measurements and improve the distinction between the two keys, we can add a warm-up phase before the timing measurements.

The warm-up phase consists in performing a certain number of decryption operations before the timing measurements.
In this way, the CPU can load the necessary data and instructions into the cache, and the branch predictor can learn the patterns of the algorithm, which can help to reduce the variance of the timing measurements.
The warm-up phase is a common technique used in performance benchmarking to ensure that the measurements are more stable and representative of the actual performance of the algorithm.

The obtained results shown on @fig4 have a much better distinction between the two keys compared to the previous results shown on @fig3.

```python
%| echo: false
%| raw: false
%| grid-inset: 6pt
%| label: fig4

samples_stats_warmup_0 = get_samples_stats(RSA_instance, 0, num_samples=10000, disable_gc=True, warmup_reps=500, progress_bar=False) / 1e6
samples_stats_warmup_1 = get_samples_stats(RSA_instance, 1, num_samples=10000, disable_gc=True, warmup_reps=500, progress_bar=False) / 1e6

plot_distributions(samples_stats_warmup_0, samples_stats_warmup_1, percentile=25, title="Timing measurements with garbage collection disabled and warm-up phase")
```




Personally, I have tried to implement the attack in Rust and C++ to try to reduce the noise caused by the Python interpreter and its optimizations, but the attack was still not successful at all in recovering the private key due to the high noise caused by the CPU cache effects, branch prediction, and other optimizations.

I have tried to implement a simple version of the timing attack on RSA in Python, based on the square-and-multiply algorithm for modular exponentiation.

The code contains two versions of the attack:
- A simple version that does not take into account the impact of previous errors on the variance, which can lead to a higher number of errors in the recovered private key.
- An improved version that manage a fixed size list of the best guesses for the private key, and that compute each time the new guess on all the list of best guesses, allowing to avoid the impact of previous errors on the variance and thus reduce the number of errors in the recovered private key.
  Note that if the list of best guesses contains only guesses with some errors, the attack can still fail, but in practice, it allows to significantly reduce the number of errors in the recovered private key.

However, the attack was not successful at all in recovering the private key, even with the improved version.
Indeed, Python introduces a lot of noise in the timing measurements, such as:
- The garbage collector, which can be triggered at any time and can cause significant delays in the execution of the code.
- The optimization which can change the algorithm used for multiplication depending on the size of the numbers, leading to different timing measurements for the same operations.
- The branch prediction that can cause variability in the timing measurements based on the input values and the internal state of the algorithm.
- CPU cache effects that can cause variability in the timing measurements based on the memory access patterns of the algorithm.
- Other CPU and Python optimizations that can introduce variability in the timing measurements.
These sources of noise have totally masked the timing variations caused by the square-and-multiply algorithm, making it impossible to recover the private key using the timing attack, even with a large number of repetitions of timing measurements (up to 100k messages and 10000 repetitions in Rust), the disabling of the garbage collector and the addition of a delay before each timing measurement to try to reduce the impact of the optimizations and branch prediction.

== Fermat's factorization method

The private key $d$ in RSA is computed based on the prime factors $p$ and $q$ of the modulus $n$.
So another way to recover the private key $d$ is to factor the modulus $n$ into its prime factors $p$ and $q$, and then compute $d$ using the formula $d equiv e^(-1) mod phi(n)$ with $phi(n) = (p - 1)(q - 1)$ the Euler's totient function.
The inverse of $e$ modulo $phi(n)$ can be computed using the Extended Euclidean Algorithm, which is an efficient method for computing the greatest common divisor of two integers and their multiplicative inverse.

But factoring large integers is a computationally hard problem, and the security of RSA relies on this fact.

However, if $p$ and $q$ are close to each other, meaning that the difference between $p$ and $q$ is small, then it becomes easier to factor $n$ using Fermat's factorization method.

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

The Fermat's factorization method consists in finding the smallest integer $x$ such that $y^2 = x^2 - n$ is a perfect square, meaning that $y$ is an integer.

Once we find such an integer $x$, we can compute $y$ as $y = sqrt(x^2 - n)$, and then we can obtain the prime factors $p$ and $q$ as described above.

So the algorithm can be summarized as follows:

1. Compute $x = ceil(sqrt(n))$.
2. Compute $y^2 = x^2 - n$.
3. If $y^2$ is a perfect square, then $y = sqrt(y^2)$ and we can compute $p = x - y$ and $q = x + y$.
4. Otherwise, increment $x$ and repeat from step 2.