Heyyy !!! You're an expert in cryptography and side-channel attacks, and you want to create a mini-project to demonstrate timing attacks on RSA.

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
            # Add extra time for multiplication step if bit is 1 in a first simple implementation
            time.sleep(0.001)  # Simulate extra time for multiplication
        else:
            R = s
        x = x >> 1  # Divide exponent by 2
        s = R**2 % n  # Square s
    return R
```

I want first that you analyze how the timing of this algorithm can leak by adding some extra time for the multiplication step if exponent bit is 1.

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

The code must implement both versions.
The code must also implement the two versions of the square-and-multiply algorithm: one where the time leaks information (with the extra sleep) and one that is normal implemented with no extra sleep.

The code must use a simple local server to simulate the RSA decryption service, and a client script to perform the attack and measure the timings.

The server should listen for incoming requests, perform the RSA decryption using one of the square-and-multiply algorithm, and return the result.
Note that first, the server should generate the RSA keys, export the public key and keep the private key secret. To generate the keys, 

The client script should send multiple requests with different inputs, measure the time taken for each request and store the times for analysis.
Then, it should implement the two attack algorithms to recover the bits of the secret exponent based on the timing measurements.

At the end, the client should be able to decode the message "Bravo ! Je suis épousplouffé par ta maîtrise du timing attack sur RSA !" using the recovered exponent and the public key, and print the decoded message to confirm the success of the attack.

Finally, the code should include a mitigation strategy to make the square-and-multiply algorithm constant-time, and compare the results of the attack on both the vulnerable and mitigated versions.


<!-- Version that don't follow the paper !!! - Simulate for m values of y the execution of the square-and-multiply algorithm up to bit b (which is set to 1), and measure the hamming weight for the result R_b. This gives a model of the cost of the multiplication step when bit b is 1.
- Send the m values to the server, which will execute the full algorithm with the actual secret exponent x and measure the time taken for each input y.
- Compute the correlation between the measured times and the hamming weights of R_b to determine if bit b is likely 0 or 1. Use the Pearson correlation coefficient for this analysis. If rho is around 0, it suggests that bit b is likely 0, while a significant positive correlation suggests that bit b is likely 1. -->



Then, I want you to implement a simple RSA decryption service that uses this algorithm in a non-constant time manner, and create a script to measure the time taken for different inputs.