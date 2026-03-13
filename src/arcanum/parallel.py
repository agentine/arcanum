"""Parallel key generation using multiprocessing.

When ``poolsize > 1`` is passed to :func:`newkeys`, prime generation
is distributed across multiple CPU cores for faster key generation.
"""

from __future__ import annotations

import multiprocessing
from typing import TYPE_CHECKING

from arcanum import prime

if TYPE_CHECKING:
    from arcanum.key import PrivateKey, PublicKey


def _generate_prime(nbits: int) -> int:
    """Worker function for parallel prime generation."""
    return prime.getprime(nbits)


def _find_p_q_parallel(
    nbits: int,
    poolsize: int,
    accurate: bool = False,
    exponent: int = 65537,
) -> tuple[int, int]:
    """Find p and q using a multiprocessing pool.

    Generates candidate primes in parallel and picks the first valid pair.
    """
    from arcanum import common

    shift = nbits // 2
    pbits = nbits - shift
    qbits = shift

    with multiprocessing.Pool(poolsize) as pool:
        while True:
            # Generate candidates in parallel.
            p_results = pool.starmap(_generate_prime, [(pbits,)] * poolsize)
            q_results = pool.starmap(_generate_prime, [(qbits,)] * poolsize)

            for p in p_results:
                for q in q_results:
                    if p == q:
                        continue
                    if p < q:
                        p, q = q, p

                    n = p * q
                    if accurate and common.bit_size(n) != nbits:
                        continue
                    if not accurate and common.bit_size(n) < nbits:
                        continue

                    phi_n = (p - 1) * (q - 1)
                    if not prime.are_relatively_prime(exponent, phi_n):
                        continue

                    return p, q


def newkeys(
    nbits: int,
    accurate: bool = False,
    poolsize: int = 2,
    exponent: int = 65537,
) -> "tuple[PublicKey, PrivateKey]":
    """Generate an RSA key pair using parallel prime generation.

    Args:
        nbits: Number of bits for the modulus.
        accurate: If True, ensure the modulus has exactly *nbits* bits.
        poolsize: Number of parallel worker processes.
        exponent: The public exponent (default 65537).

    Returns:
        A tuple of ``(PublicKey, PrivateKey)``.
    """
    from arcanum.key import PublicKey, PrivateKey

    if nbits < 16:
        raise ValueError("Key size must be at least 16 bits")

    p, q = _find_p_q_parallel(nbits, poolsize, accurate=accurate, exponent=exponent)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    d = pow(exponent, -1, phi_n)

    return (
        PublicKey(n=n, e=exponent),
        PrivateKey(n=n, e=exponent, d=d, p=p, q=q),
    )
