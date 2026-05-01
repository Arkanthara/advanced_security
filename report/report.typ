// Main report file
#import "template.typ": make-report, report-footnote
#import "metadata.typ": my-report

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

== Timing attacks on RSA

As mentioned earlier, the security of RSA relies on the difficulty of factoring large integers, but the implementation of RSA can introduce vulnerabilities that can be exploited by attackers.
The goal of the attacker is to recover the unknown private key $d$ thanks to the knowledge of the public key $(n, e)$ and the ability to perform encryption and decryption operations using the RSA algorithm.

Timing attacks on RSA exploit the fact that the time it takes to perform certain operations in the RSA algorithm can vary based on the input values and the internal state of the algorithm.
For example, the time it takes to perform the modular exponentiation operation $c^d mod n$ can vary based on the value of $d$ and the input ciphertext $c$.
Indeed, a simple implementation of the modular exponentiation operation can use a square-and-multiply algorithm, as described in the following python code:

```python
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

The base idea of this algorithm is that computing $y^x$ can be done by decomposing $x$ by powers of 2, then computing $y$ raised to these powers of 2 and multiplying the results together.

For instance, if $x = 13 = 1101_2$, then $y^x mod n= y^13 mod n = (y^8 mod n) dot (y^4 mod n) dot (y^1 mod n)$.

So the efficiency of the algorithm comes from the fact that it iteratively computes $y^x mod n$ by performing small multiplication and squaring operations thanks to the modular properties instead of performing a single large exponentiation operation.

