# RSA DTA and Fermat Demo

Clean Python version of the RSA timing demo.

The sample collection is server-style: the attacker sends a message and only
receives the total time taken by RSA decryption with the private key `d`.

The attack then:

- estimates the square cost, which is independent of `d` in the right-to-left loop
- removes that common square cost from the total timings
- estimates the branch-dependent multiply cost for H0 and H1
- chooses the bit whose cost vector has the stronger Pearson correlation
- recovers `d` separately with Fermat factorization when `p` and `q` are close

Run with uv:

```powershell
uv run python rsa_dta_demo.py --samples 200 --reps 1 --recover-bits 12 --key-bits 128
```

Options:

```text
--samples       number of messages sent to the server
--reps          repeated decryptions per message timing
--recover-bits  low bits of d to recover
--key-bits      RSA modulus size, for example 128, 512, 1024, 2048
--seed          deterministic random seed, decimal or 0x-prefixed
```

The recovered bit string is printed least significant bit first because the
decryption scans `d` from low bit to high bit.

This version is intentionally closer to a real timing oracle than the previous
per-operation demo, so the attack is noisier. Increase `--samples` or `--reps`
when using larger keys or longer recovered prefixes.
