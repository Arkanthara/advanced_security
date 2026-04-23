"""Core RSA utilities used by the timing-attack mini-project."""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Iterable

from Crypto.Util.number import getPrime


@dataclass(frozen=True)
class RSAKeyPair:
    """Container for a toy RSA key pair.

    Parameters
    ----------
    n:
        RSA modulus.
    e:
        Public exponent.
    d:
        Private exponent.
    p:
        First prime factor of ``n``.
    q:
        Second prime factor of ``n``.
    """

    n: int
    e: int
    d: int
    p: int
    q: int


def generate_rsa_keypair(key_size_bits: int, e: int = 65537) -> RSAKeyPair:
    """Generate a small RSA key pair for timing-attack demonstrations.

    Parameters
    ----------
    key_size_bits:
        Target modulus size in bits.
    e:
        Public exponent.

    Returns
    -------
    RSAKeyPair
        A freshly generated key pair.
    """

    if key_size_bits < 16:
        raise ValueError("key_size_bits must be >= 16")

    p_bits = key_size_bits // 2
    q_bits = key_size_bits - p_bits

    while True:
        p = getPrime(p_bits)
        q = getPrime(q_bits)
        if p == q:
            continue

        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) != 1:
            continue

        n = p * q
        d = pow(e, -1, phi)
        return RSAKeyPair(n=n, e=e, d=d, p=p, q=q)


def int_to_lsb_bits(value: int, width: int | None = None) -> list[int]:
    """Convert an integer into an LSB-first bit list.

    Parameters
    ----------
    value:
        Integer to convert.
    width:
        Optional output width. If provided, the result is zero-padded or
        truncated to this width.

    Returns
    -------
    list[int]
        Bit list where index 0 is the least-significant bit.
    """

    if value < 0:
        raise ValueError("value must be non-negative")

    bits: list[int] = []
    current = value
    while current > 0:
        bits.append(current & 1)
        current >>= 1

    if not bits:
        bits = [0]

    if width is None:
        return bits

    if len(bits) < width:
        bits.extend([0] * (width - len(bits)))
    return bits[:width]


def lsb_bits_to_int(bits: Iterable[int]) -> int:
    """Convert an LSB-first bit sequence back to an integer.

    Parameters
    ----------
    bits:
        Bits where position 0 is the least-significant bit.

    Returns
    -------
    int
        Integer represented by the bits.
    """

    value = 0
    for idx, bit in enumerate(bits):
        if bit not in (0, 1):
            raise ValueError("bits must contain only 0 and 1")
        if bit == 1:
            value |= 1 << idx
    return value


def max_plaintext_block_size(n: int) -> int:
    """Compute the plaintext block size in bytes for textbook RSA.

    Parameters
    ----------
    n:
        RSA modulus.

    Returns
    -------
    int
        Maximum number of bytes per block such that ``m < n``.
    """

    if n <= 255:
        return 1
    return max(1, (n.bit_length() - 1) // 8)


def encode_message_blocks(message: str, n: int) -> tuple[list[int], list[int]]:
    """Split a UTF-8 message into RSA blocks.

    Parameters
    ----------
    message:
        Input plaintext.
    n:
        RSA modulus.

    Returns
    -------
    tuple[list[int], list[int]]
        RSA integer blocks and original byte lengths per block.
    """

    raw = message.encode("utf-8")
    block_size = max_plaintext_block_size(n)
    blocks: list[int] = []
    lengths: list[int] = []

    for offset in range(0, len(raw), block_size):
        chunk = raw[offset : offset + block_size]
        blocks.append(int.from_bytes(chunk, byteorder="big"))
        lengths.append(len(chunk))

    return blocks, lengths


def decode_message_blocks(blocks: list[int], lengths: list[int]) -> str:
    """Decode UTF-8 plaintext from RSA integer blocks.

    Parameters
    ----------
    blocks:
        Decrypted RSA blocks as integers.
    lengths:
        Original plaintext byte lengths for each block.

    Returns
    -------
    str
        Decoded plaintext.
    """

    if len(blocks) != len(lengths):
        raise ValueError("blocks and lengths must have the same size")

    raw = bytearray()
    for block, chunk_len in zip(blocks, lengths):
        raw.extend(block.to_bytes(chunk_len, byteorder="big"))
    return raw.decode("utf-8")


def encrypt_blocks(blocks: Iterable[int], e: int, n: int) -> list[int]:
    """Encrypt integer blocks with textbook RSA."""

    return [pow(block, e, n) for block in blocks]


def decrypt_blocks(blocks: Iterable[int], d: int, n: int) -> list[int]:
    """Decrypt integer blocks with textbook RSA."""

    return [pow(block, d, n) for block in blocks]
