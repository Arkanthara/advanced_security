"""RSA timing oracle and square-and-multiply implementations."""

from __future__ import annotations

from dataclasses import dataclass
import random
import time
from typing import Iterable

from .rsa_core import (
    RSAKeyPair,
    decode_message_blocks,
    encode_message_blocks,
    encrypt_blocks,
)

CHALLENGE_MESSAGE = (
    "Bravo ! Je suis épousplouffé par ta maîtrise du timing attack sur RSA !"
)


@dataclass(frozen=True)
class LeakageConfig:
    """Timing leakage model for the vulnerable square-and-multiply.

    Parameters
    ----------
    base_sleep_s:
        Base delay (in seconds) added when a multiplication is performed
        for a ``1`` bit of the secret exponent.
    scale_sleep_s:
        Extra delay factor driven by the intermediate multiplication output.
    response_jitter_s:
        Standard deviation of additional Gaussian response jitter.
    """

    base_sleep_s: float = 0.0008
    scale_sleep_s: float = 0.0012
    response_jitter_s: float = 0.00015


def leak_delay_for_value(value: int, n: int, config: LeakageConfig) -> float:
    """Compute the sleep delay used by the leaky implementation.

    Parameters
    ----------
    value:
        Intermediate multiplication result ``R``.
    n:
        RSA modulus.
    config:
        Leakage model parameters.

    Returns
    -------
    float
        Delay in seconds.
    """

    bit_norm = value.bit_count() / max(1, n.bit_length())
    return config.base_sleep_s + (config.scale_sleep_s * bit_norm)


def square_and_multiply_step(
    *,
    s: int,
    y_mod: int,
    n: int,
    bit: int,
    leaky: bool,
    config: LeakageConfig,
    do_sleep: bool,
) -> tuple[int, float]:
    """Run one LSB-first square-and-multiply step.

    Parameters
    ----------
    s:
        Current internal state.
    y_mod:
        Base value modulo ``n``.
    n:
        RSA modulus.
    bit:
        Exponent bit to process.
    leaky:
        If ``True``, apply timing leak on multiplication steps.
    config:
        Leakage model.
    do_sleep:
        If ``True``, call ``time.sleep`` with the modeled delay.

    Returns
    -------
    tuple[int, float]
        New state ``s`` and timing contribution for this step.
    """

    if bit == 1:
        r = (s * y_mod) % n
        delay_s = leak_delay_for_value(r, n, config) if leaky else 0.0
        if do_sleep and delay_s > 0.0:
            time.sleep(delay_s)
    else:
        r = s
        delay_s = 0.0

    s_next = (r * r) % n
    return s_next, delay_s


def square_and_multiply(
    y: int,
    exponent: int,
    n: int,
    *,
    leaky: bool,
    config: LeakageConfig,
    do_sleep: bool = True,
) -> tuple[int, float]:
    """Compute ``y**exponent mod n`` using LSB-first square-and-multiply.

    Parameters
    ----------
    y:
        Base value.
    exponent:
        Exponent value.
    n:
        RSA modulus.
    leaky:
        Whether to use the timing-leaky behavior.
    config:
        Leakage configuration.
    do_sleep:
        If ``True``, apply real sleep delays.

    Returns
    -------
    tuple[int, float]
        Decryption result and modeled accumulated delay.
    """

    if exponent < 0:
        raise ValueError("exponent must be non-negative")

    y_mod = y % n
    s = 1
    r = 1
    total_delay_s = 0.0
    x = exponent

    while x > 0:
        bit = x & 1
        s, step_delay = square_and_multiply_step(
            s=s,
            y_mod=y_mod,
            n=n,
            bit=bit,
            leaky=leaky,
            config=config,
            do_sleep=do_sleep,
        )
        if bit == 1:
            r = (r * y_mod) % n
        r = s if bit == 0 else r
        total_delay_s += step_delay
        x >>= 1

    if exponent == 0:
        r = 1
    else:
        # Keep output consistent with the loop recurrence.
        # `s` holds R^2 mod n from the last step, while `r` tracks the true R.
        pass
    return r % n, total_delay_s


def square_and_multiply_normal(
    y: int, exponent: int, n: int, config: LeakageConfig
) -> tuple[int, float]:
    """Normal implementation with no intentional sleep leak."""

    return square_and_multiply(
        y=y,
        exponent=exponent,
        n=n,
        leaky=False,
        config=config,
        do_sleep=False,
    )


def square_and_multiply_leaky(
    y: int, exponent: int, n: int, config: LeakageConfig
) -> tuple[int, float]:
    """Leaky implementation with extra multiplication-time sleep."""

    return square_and_multiply(
        y=y,
        exponent=exponent,
        n=n,
        leaky=True,
        config=config,
        do_sleep=True,
    )


def simulate_prefix_timing(y: int, prefix_bits_lsb: Iterable[int], n: int, config: LeakageConfig) -> float:
    """Simulate expected timing for known exponent prefix bits.

    Parameters
    ----------
    y:
        Input ciphertext.
    prefix_bits_lsb:
        Known/guessed exponent bits in LSB-first order.
    n:
        RSA modulus.
    config:
        Leakage model.

    Returns
    -------
    float
        Expected cumulative leak delay contributed by the prefix.
    """

    y_mod = y % n
    s = 1
    cumulative = 0.0

    for bit in prefix_bits_lsb:
        s, step_delay = square_and_multiply_step(
            s=s,
            y_mod=y_mod,
            n=n,
            bit=bit,
            leaky=True,
            config=config,
            do_sleep=False,
        )
        cumulative += step_delay

    return cumulative


@dataclass
class RSATimingOracle:
    """Local RSA decryption oracle used by the TCP server.

    Parameters
    ----------
    keypair:
        RSA key pair.
    mode:
        Either ``"leaky"`` or ``"normal"``.
    config:
        Leakage configuration.
    random_seed:
        Optional seed for response jitter.
    """

    keypair: RSAKeyPair
    mode: str
    config: LeakageConfig
    random_seed: int | None = None

    def __post_init__(self) -> None:
        if self.mode not in {"leaky", "normal"}:
            raise ValueError("mode must be 'leaky' or 'normal'")
        self._rng = random.Random(self.random_seed)

        plain_blocks, block_lengths = encode_message_blocks(CHALLENGE_MESSAGE, self.keypair.n)
        self._challenge_cipher_blocks = encrypt_blocks(
            plain_blocks, self.keypair.e, self.keypair.n
        )
        self._challenge_block_lengths = block_lengths

    @property
    def n(self) -> int:
        """Return the RSA modulus."""

        return self.keypair.n

    def decrypt(self, ciphertext: int) -> int:
        """Decrypt one ciphertext with the selected implementation."""

        y = ciphertext % self.keypair.n
        if self.mode == "leaky":
            result, _ = square_and_multiply(
                y=y,
                exponent=self.keypair.d,
                n=self.keypair.n,
                leaky=True,
                config=self.config,
                do_sleep=True,
            )
        else:
            result, _ = square_and_multiply(
                y=y,
                exponent=self.keypair.d,
                n=self.keypair.n,
                leaky=False,
                config=self.config,
                do_sleep=False,
            )

        if self.config.response_jitter_s > 0:
            jitter = self._rng.gauss(0.0, self.config.response_jitter_s)
            if jitter > 0:
                time.sleep(jitter)

        return result

    def simulate_timing(self, ciphertext: int) -> float:
        """Compute model timing without executing real sleep.

        Parameters
        ----------
        ciphertext:
            Ciphertext integer.

        Returns
        -------
        float
            Expected delay in seconds.
        """

        y = ciphertext % self.keypair.n
        _, modeled = square_and_multiply(
            y=y,
            exponent=self.keypair.d,
            n=self.keypair.n,
            leaky=(self.mode == "leaky"),
            config=self.config,
            do_sleep=False,
        )
        return modeled

    def public_info(self) -> dict:
        """Return public metadata exposed by the service."""

        return {
            "n": self.keypair.n,
            "e": self.keypair.e,
            "key_bits": self.keypair.n.bit_length(),
            "private_exponent_bits": self.keypair.d.bit_length(),
            "mode": self.mode,
            "challenge_cipher_blocks": self._challenge_cipher_blocks,
            "challenge_block_lengths": self._challenge_block_lengths,
            "challenge_block_count": len(self._challenge_cipher_blocks),
            "leakage_config": {
                "base_sleep_s": self.config.base_sleep_s,
                "scale_sleep_s": self.config.scale_sleep_s,
                "response_jitter_s": self.config.response_jitter_s,
            },
        }

    def decrypt_challenge_with_d(self, d_guess: int) -> str:
        """Decrypt the challenge text with a guessed private exponent."""

        plain_blocks = [pow(c, d_guess, self.keypair.n) for c in self._challenge_cipher_blocks]
        return decode_message_blocks(plain_blocks, self._challenge_block_lengths)
