Heyyy !!! You're an expert in cryptography and side-channel attacks, and you want to create a mini-project to demonstrate timing attacks on RSA fast exponentiation.

I want that you study the Square-and-Multiply algorithm for RSA decryption, and how it can leak information through timing variations.

The algorithm is as follows for R = y^x mod n with x being w bits long:

```python
import time

def square_and_multiply(y, x, n):
    s = 1
    y %= n
    while x > 0:
        if (x % 2) == 1:  # If exponent is odd
            R = (s * y) % n
        else:
            R = s
        x = x >> 1  # Divide exponent by 2
        s = R**2 % n  # Square s
    return R
```

I want first that you analyze how the timing of this algorithm can leak information if exponent bit is 1.

The attack works like this:
1. The attacker knows the first 0..b-1 bits of the secret exponent x. He wants to determine the b-th bit. As he knows the first b-1 bits, he can simulate the algorithm up to that point for each y.
2. If bit b is 1, the algorithm will perform an extra multiplication step, which takes more time than if bit b is 0.
3. By measuring the time taken for different inputs y, the attacker can statistically determine whether bit b is 0 or 1 based on the timing variations.
4. By repeating this process for each bit of the exponent, the attacker can eventually recover the entire secret exponent x.

A little of theory before we start coding:

- The total time taken for y_i is given by: T_i = noise + sum_{j=0}^{w-1} t_j with t_j the time taken for the j-th bit of the exponent.

- We make an hypothesis on x_b, then we compute t(y_i, x_b) = sum_{j=0}^{b-1} t_j.

- We substract t(y_i, x_b) from T_i to get T'_i = T_i - t(y_i, x_b) = noise + sum_{j=b}^{w-1} t_j.

- If hypothesis is correct, Var(noise + sum_{j=b}^{w-1} t_j) is Var(noise) + (w - b) * Var(t_j).

- If hypothesis is wrong and only the first c bits are correct, Var(noise + sum_{j=b}^{w-1} t_j) is Var(noise) + (w - b + 2c) * Var(t_j).

So for the algorithm, I want two versions for exponent recovery:

Version 1 (simple):

- We compute for m values of y the server execution time T_i for each input y_i.
- We compute the expected time t(y_i, x_b) for each input y_i based on our hypothesis for bit b.
- We compute T'_i = T_i - t(y_i, x_b) for each input y_i.
- We compute the variance of T'_i for each hypothesis (bit b = 0 or 1).
- We compare the variances for both hypotheses. The hypothesis with the lower variance is more likely to be correct, as it suggests that the timing variations are more consistent with the expected behavior of the algorithm for that bit value. If the variance for bit b = 1 is significantly lower than for bit b = 0, it suggests that bit b is likely 1, and vice versa.
- If the variance difference is not significant, we may need to collect more samples, or go back to the previous bits to check its correctness.

Version 2 (error correction):

- We compute for m values of y the server execution time T_i for each input y_i.
- We maintain a list of candidate x_b values (initially [0, 1]) and their corresponding variances.
- For each candidate x_b, we compute T'_i = T_i - t(y_i, x_b) for each input y_i and compute the variance of T'_i.
- We update the list of candidates by keeping only those with the lowest variances. For example, we can keep the top 20% of candidates with the lowest variances, or keep a fixed number of candidates (e.g., 10) with the lowest variances.
- We repeat this process for each bit b, refining our candidates based on the variance analysis until we narrow down to the most likely value for each bit of the exponent.

The code must implement both versions in RUST.

The code must be:
- The most simple possible, with numpy style documnentation and comments to explain the logic.
- Organized for clarity.
- As small as possible, while still being functional and demonstrating the attack effectively.
- Meaningful variable names and modular functions to enhance readability and maintainability.

You must avoid all optimizations that could make the timing measurements less accurate.
The key to test are the 2048 bits keys following (so use the good library to manage big integers which is not constent time for multiplication and don't have optimizations...):
p_A = 13109499994810966779468866046493465498469807493634236479294124421385342920350717814807375283698575766763256101470694189234369358996750113963585617491399169
q_A = 9497561827984502554523100157901534504433126034087863778629488755692649311435921364240405549590851856701860175924335776598684751639633322074428628372725777
n_A = p_A * q_A
e_A = 4574830074548708213
m_1 = 123456789132456789
d_A = 1685394382767324790326942621450485552187209875614438478305225564629345944620726038114923060947436330701451901921041511234432041036987266468290187679773130363479895993621867708066144608084390089775045890165825736468637468786667820591136139480545376198614216373031208691260339805721685482401743494212035728605

The message to decode is "Bravo ! Je suis épousplouffé par ta maîtrise du timing attack sur RSA !", which is represented as an integer (m_1) that is encrypted with the public key (n_A, e_A) and that we want to decrypt using the recovered private key (n_A, d_A).

I want to be able to choose the number of samples to collect and the number of bits to recover.
To increase the accuracy of the attack, you can perform multiple measurements to amplify the timing differences between the two hypotheses.
I want to be able to choose the number of repetitions.

I want that you print the progress of the attack in real-time, showing which bit is currently being recovered, the variance analysis results for each hypothesis, and the current list of candidate exponent values (for version 2).
I want also that you tell each time if the recovered bit is correct or not, based on the known private key, to validate the attack's progress.

Please, for the accuracy of the method, disable all optimizations such as branch prediction, loop unrolling etc. to ensure that the timing measurements reflect the actual execution time of the algorithm without any interference from compiler optimizations.

To increase the accuracy of the attack, you can perform multiple measurements for each input y and take the median time to reduce the impact of outliers and noise in the timing data.
Between each measurement, you must introduce a very small delay (e.g., time.sleep) to allow the system to stabilize and reduce the impact of transient system load on the timing measurements.

Note that you must disable the garbage collector during the timing measurements to reduce noise, and remove the outliers from the timing data to improve the accuracy of the variance analysis.

I want also that you use parallel processing to speed up the collection of timing measurements, especially for larger key sizes where more samples may be needed for a successful attack.
To do that, use joblib.

The code must update the collection of data from server and the attack progress in real-time.
You can use a simple progress bar (e.g., tqdm) to show the progress of the attack and the collection of timing measurements.
You must base your implementation on the given implementation of RSA.

The code must create a simple local server to simulate the RSA decryption service, and a client script to perform the attack and measure the timings.

The server should listen for incoming requests, perform the RSA decryption, and return the result.
Note that first, the server should generate the RSA keys, export the public key and keep the private key secret.

The client script should send multiple requests with different inputs, measure the time taken for each request and store the times for analysis.
Then, it should implement the two attack algorithms to recover the bits of the secret exponent based on the timing measurements.

At the end, the client should be able to decode the message "Bravo ! Je suis épousplouffé par ta maîtrise du timing attack sur RSA !" using the recovered exponent and the public key, and print the decoded message to confirm the success of the attack.

Finally, I want that in a notebook you test the algorithm for different key sizes (from 32 to 2048 bits... Try to use existing implementations from libraries !!!) and analyze accuracy and performance of the attack for each key size, and plot the results to show how the attack performs as the key size increases. I want a study of the number of samples needed for a successful attack as the key size increases and the total execution time.

Please deliver the code for the server, the client, and the notebook for testing and analysis.

The code must be as simple as possible, with numpy style documnentation and comments to explain the logic. The code should be modular and organized for clarity.


<!-- Version that don't follow the paper !!! - Simulate for m values of y the execution of the square-and-multiply algorithm up to bit b (which is set to 1), and measure the hamming weight for the result R_b. This gives a model of the cost of the multiplication step when bit b is 1.
- Send the m values to the server, which will execute the full algorithm with the actual secret exponent x and measure the time taken for each input y.
- Compute the correlation between the measured times and the hamming weights of R_b to determine if bit b is likely 0 or 1. Use the Pearson correlation coefficient for this analysis. If rho is around 0, it suggests that bit b is likely 0, while a significant positive correlation suggests that bit b is likely 1. -->



Then, I want you to implement a simple RSA decryption service that uses this algorithm in a non-constant time manner, and create a script to measure the time taken for different inputs.