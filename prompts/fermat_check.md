Heyyy !!! Now I want you to create a mini-project to demonstrate Fermat's factorization method.
Fermat's factorization method is based on the difference of squares. It works by expressing a composite number n as a difference of two squares, which can then be factored to find its prime factors.

The algorithm is as follows for n = p * q:
1. Start with x = ceil(sqrt(n)).
2. Compute y^2 = x^2 - n.
3. If y^2 is a perfect square, then y = sqrt(y^2).
4. Update x = x + 1 and repeat steps 2-3 until y^2 is a perfect square.
4. Return the factors (x - y) and (x + y).

I have already implemented RSA, can you implement Fermat's factorization method in Python and use it to factor the modulus n of the RSA key pair you generated?
