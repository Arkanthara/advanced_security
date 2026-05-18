
#show figure.where(kind: "subfigure"): set figure(supplement: "Figure")

#show figure.where(kind: image): outer => {
  counter(figure.where(kind: "subfigure")).update(0)
  set figure(numbering: (..nums) => {
    let outer-nums = counter(figure.where(kind: image)).at(outer.location())
    std.numbering("1a", ..outer-nums, ..nums)
  })
  show figure.where(kind: "subfigure"): inner => {
    show figure.caption: it => context {
      std.numbering("(a)", it.counter.at(inner.location()).last())
      [ ]
      it.body
    }
    inner
  }
  outer
}
// Main report file

#import "@preview/touying:0.7.3": *
#import themes.university: *
#import themes.stargazer: *
#import "@preview/chronos:0.3.0": *
#import "@preview/pintorita:0.1.4"

#import "@preview/theorion:0.6.0": *
#import cosmos.clouds: *
#show: show-theorion

#show raw.where(lang: "pintora"): it => pintorita.render(it.text)

#import "@preview/numbly:0.1.0": numbly

#show: stargazer-theme.with(
  aspect-ratio: "16-9",
  // Fix header logo: box it with explicit height and vertical alignment  
  header-right: self => {  
    box(utils.display-current-heading(level: 1))  
    h(.2em)  
    box(height: 1.5em, baseline: 30%, image("img/unige.svg", height: 1.5em))  
  },  
  config-info(
    title: [Timing Attacks on RSA],
    subtitle: [and Fermat's factorization],
    author: [Michel Jean Joseph Donnet],
    date: datetime.today(),
    institution: [Faculty of Science, University of Geneva],
    contact: [],
    logo: image("./img/unige.svg", height: 2em),
  ),
    // transparence du décor de fond
  alpha: 12%,

  // barre de progression discrète
  progress-bar: true,

  // Palette personnalisée
  config-colors(
    // Couleur institutionnelle adoucie
    // primary: rgb("#CF0063"),
    primary: rgb("#0A7A66"),

    // Version sombre pour slides focus / contrastes
    // primary-dark: rgb("#7A0042"),
    primary-dark: rgb("#065345"),

    // Couleur du texte sur fonds colorés
    secondary: rgb("#FFFFFF"),

    // Couleur faculté (vert sarcelle)
    tertiary: rgb("#0A7A66"),

    // Fond général légèrement cassé
    neutral-lightest: rgb("#FAFAFA"),

    // Texte principal
    // neutral-darkest: rgb("#7A0042"),
    neutral-darkest: rgb("#032e26"),
  ),
)


// #set heading(numbering: numbly("{1}.", default: "1.1"))

#show raw.where(block: true): set block(fill: luma(240), inset: 1em, radius: 0.5em, width: 100%)
// #show raw.where(block: false): set block(fill: luma(240), inset: 1em, radius: 0.5em, width: 100%)
// #show raw.where(block: false): box.with(
//   fill: rgb("#e573e927"),
//   inset: (x: 3pt, y: 0pt),
//   outset: (y: 3pt),
//   radius: 2pt,
// )

#title-slide()

#outline-slide()

= Introduction

== Cryptography

#tblock(title: "Goals")[
- Confidentiality
- Integrity
- Authenticity
]

#tblock(title: "Types of cryptography")[

- Symmetric cryptography (e.g., AES)
- Asymmetric cryptography (e.g., RSA)

]
#tblock(title: "Security of cryptographic algorithms")[
- Computational hardness assumptions
- Mathematical problems (e.g., factoring large integers for RSA)
]

== RSA algorithm


#tblock(title: [Security assumption])[
- Factorization of large integers is computationally hard
]

#tblock(title: [Key generation])[
- $p$, $q$: large prime numbers
- $n = p times q$: modulus
- $e$: public exponent, coprime to $phi(n)$
- $d$: private exponent, such that $e dot d equiv 1 mod phi(n)$
]

#tblock(title: [Keys])[
- Public key: $(n, e)$
- Private key: $(n, d)$
]

#tblock(title: [Encryption])[

- Plaintext message $m$ (integer less than $n$)
- Ciphertext $c = m^e mod n$
]

#tblock(title: [Decryption])[
- Ciphertext $c$
- Plaintext message $m = c^d mod n$
]

#tblock(title: [Proof])[
$c^d mod n = (m^e)^d mod n = m^(e d) mod n = m^(1 + k phi(n)) mod n = m mod n$
]

#speaker-note[
  - Théorème d'Euler: $a^(phi(n)) equiv 1 mod n$ pour $a$ coprime à $n$
]



#pagebreak()

= Principles of RSA timing attacks

== Example Protocol


#show raw.where(block: true): set block(fill: luma(94.12%, 0%), inset: 1em, radius: 0.5em, width: 100%)

```pintora
sequenceDiagram
  participant [<actor> Client]
  participant [<database> Server]

  Client->>Server: ClientHello
  Server->>Client: ServerHello + Certificate (RSA public key)


  Client-->>Client: Generate secret
  Client-->>Client: Encrypt with server RSA public key


  Client->>Server: ClientKeyExchange (encrypted secret)

  @note left of Server: [TIMING ATTACK ZONE] Decrypt + Verify padding

  alt #d4edda Padding invalid
    Server->>Client: Alert
  else #f8d7da Padding valid
    Server->>Client: Finished
  end

```
#show raw.where(block: true): set block(fill: luma(240), inset: 1em, radius: 0.5em, width: 100%)



#speaker-note[
  - Établissement canal sécurisé
  - Échange client-serveur
  - Attaquant envoie des messages chiffrés au serveur et mesure le temps de déchiffrement
]

== Square-and-multiply algorithm

The execution time can vary based on the value of the exponent and the input ciphertext, as explained by Paul C. Kocher @kocher1996timing.

```python
def square_and_multiply(y, x, n):
    s = 1
    y %= n

    while x > 0:
        if (x % 2) == 1:
            s = (s * y) % n  # Extra multiplication here when x is odd !
        y = (y * y) % n
        x = x >> 1

    return s
```
== Exploiting timing variations


#tblock(title: [Online])[
+ Attacker sends random ciphertexts $c$ to the server
+ Measures time for decryption $c^d mod n$
]

#tblock(title: [Offline])[

+ For each bit of $d$, guess bit value (0 or 1)
+ Compute expected timing based on guess
+ Analyze variance of timing differences
  - Low variance: guess likely correct
  - High variance: guess likely incorrect
]

= Mathematical analysis

#tblock(title: [Probability of a correct guess])[

$ P(x_b) prop product_(i=1)^N F(T_i - t(c_i, x_b) | x_b) $

with $F$: probability distribution of timing error according to $x_b$.


$ P(x_b = 1) = (product_(i=1)^N F(T_i - t(c_i, x_b) | x_b = 1))/(product_(i=1)^N F(T_i - t(c_i, x_b) | x_b = 0) + product_(i=1)^N F(T_i - t(c_i, x_b) | x_b = 1)) $

- $P(x_b = 1) > 0.5 ==> x_b = 1$
- $P(x_b = 1) < 0.5 ==> x_b = 0$
]

#pagebreak()

== Variance analysis

// #warning-block[
//   $F$ cannot be directly computed
// ]

#tblock(title: [Assumptions])[
- $T_i = sum_(k = 1)^l t_k + epsilon$
- $x_(b - 1)$ is known 
]


#tblock(title: [Case with correct guess $x_b$])[
$ T_i - t(c_i, x_b) = sum_(k = b + 1)^l t_k + epsilon $
]

#tblock(title: [Case with incorrect guess $x_b$])[
$ T_i - t(c_i, x_b) = sum_(k = b + 1)^l t_k + epsilon + (t_b_("correct") - t_b_("incorrect")) $
]

#pagebreak()

#tblock(title: [Impact of previous errors on the variance])[
- The $c$-th bit of $d$ is incorrect
- $c < b - 1$

$ T_i - t(c_i, x_b) = sum_(k = b + 1)^l t_k + epsilon + (sum_(k = c)^b (t_k_("correct") - t_k_("incorrect"))) $
]

#speaker-note[
  - $c$ incorrect
  - Toutes les étapes suivantes sont incorrectes
]

= Pearson-based timing attack

== Pearson correlation coefficient

#let Cov = math.op("Cov")
#let Var = math.op("Var")

#tblock(title: [Definition])[
Measure of the linear correlation between two variables $X$ and $Y$
$ r = Cov(X, Y)/(sigma_X sigma_Y) $

- $r$ close to 1: strong positive correlation
- $r$ close to -1: strong negative correlation
- $r$ close to 0: no linear correlation
]

== Designing the model of expected timings

#tblock(title: [Goal])[
Design a model that explains variations in execution time.
]


#tblock(title: [Model])[Hamming weight of intermediate values in square-and-multiply algorithm]

= Challenges in implementation

== Sources of noise

- CPU cache effects
- Branch prediction
- Garbage collection
- Multiplication optimizations
- Other optimizations (e.g., loop unrolling, instruction reordering, just-in-time compilation)

#pagebreak()

== Reducing the impact of noise

#figure(image(".typst_pyexec/figures/cell_5_1_2.svg", width: 80%
), caption: [Distribution of timing measurements], kind: image)

#speaker-note[
  - Désactivation du garbage collector
  - Répétition des mesures de temps
  - Phase de warm-up
  - Utilisation de l'estimateur minimum plutôt que la moyenne
]

#pagebreak()

#tblock(title: [Garbage collector])[
  Disable garbage collector during timing measurements @kocher_jupyter
]

#tblock(title: [Measurement repetitions])[
  Using repeated measurements to reduce noise

#important-block([
  - Noise is additive
  - High variance in timing measurements

  *$==>$* #text("MINIMUM", weight: "extrabold", fill: red) *AS ESTIMATOR !*

])
]

#speaker-note[
  - Warm-up phase pour réduire l'impact du cache et de la prédiction de branchement
  - Pas nécessaire car utilisation du minimum
]

#pagebreak()

= Results

== Variance-based timing attack

#tblock(title: [Implementation])[
- Python without noise reduction
  - #text("Failed", fill: red)
- Python with noise reduction and average as estimator
  - #text("Failed", fill: red)
- C++ and Rust with average
  - #text("Failed", fill: red)
- Python using *minimum* as estimator
  - #text("Success", fill: green)
]

#pagebreak()

#tblock(title: [Results])[
- Recovered 5 bits of private key $d$
- Time taken: #text("13 hours", fill: red) on AMD Ryzen 9 7950X3D
- Configuration:
  - 1000 messages
  - 10000 repetitions
  - Assumed first 16 bits of $d$ known
  - 3 candidates per iteration
]

#pagebreak()

== Pearson-based timing attack

#tblock(title: [Using median as estimator])[
- Recovered *7/10 bits* of private key $d$
- Time taken: #text("1h30", fill: green)
- Configuration:
  - 3000 messages
  - 500 repetitions
  - Assumed first 16 bits of $d$ known
  - 3 candidates per iteration
]

#tblock(title: [Using minimum as estimator])[
- Recovered #text("9/10 bits", fill: green, weight: "bold") of private key $d$
- Time taken: #text("1h30", fill: green)
]

= Fermat's factorization

== Factorization of the modulus $n$

#tblock(title: [Requirements])[
- $n = p times q$
- $p$ and $q$ are odd primes and close to each other
]

#tblock(title: [Theory])[
- $p$ and $q$ are odd primes $==>$ there exists an integer $x$ such that $x = (p + q)/2$
- $y = x - p = q - x$
- $n = p times q = (x - y)(x + y) = x^2 - y^2$
]

#pagebreak()

#tblock(title: [Method @fermat])[
1. $x = ceil(sqrt(n))$
2. $y^2 = x^2 - n$
3. If $y^2$ is a perfect square
  - $y = sqrt(y^2)$
  - $p = x - y$
  - $q = x + y$
4. Otherwise, increment $x$ and repeat from step 2
]

#pagebreak()

== Results

#figure(image(".typst_pyexec/figures/cell_9_1.svg"), caption: [Fermat factorization with n: 2048 bit]) <fig4>

#speaker-note[
  - Derniers 30 bits de $p$ et $q$ qui diffèrent
  - Temps pour trouver le gap: 3h
  - Temps pour trouver les facteurs: moins de 1s
]

#pagebreak()

= Conclusion

Algorithms can be *mathematically secure* but still *vulnerable* to side-channel attacks that exploit *physical implementations* of the algorithms, such as timing variations in RSA decryption.

Timing attacks are *still relevant* today.

They highlight the importance of *considering* side-channel attacks when *designing* and *implementing* cryptographic systems.

#speaker-note[
  - Serveurs sont vieux, moins optimisés et programmés en langage de bas niveau (C, C++)
  - RSA est encore largement utilisé
  - TLS 1.3 a supprimé les suites de chiffrement basées sur RSA, mais de nombreux serveurs supportent encore TLS 1.2 et des versions antérieures
]

#pagebreak()


#bibliography("bibliography.bib")