"""Cryptographically secure random number generation.

Uses the ``secrets`` module for all randomness.
"""

import secrets


def read_random_bits(nbits: int) -> int:
    """Read nbits random bits and return as an integer.

    The returned integer will have exactly ``nbits`` bits — that is,
    the most significant bit is always set.

    Args:
        nbits: The number of random bits to generate. Must be positive.

    Returns:
        A random integer with exactly nbits bits.

    Raises:
        ValueError: If nbits is less than 1.
    """
    if nbits < 1:
        raise ValueError("nbits must be at least 1")

    # Generate nbits random bits
    value = secrets.randbits(nbits)

    # Ensure the most significant bit is set
    value |= 1 << (nbits - 1)

    return value


def read_random_int(maxvalue: int) -> int:
    """Return a random integer in the range [0, maxvalue).

    Args:
        maxvalue: The exclusive upper bound. Must be positive.

    Returns:
        A random integer x where 0 <= x < maxvalue.

    Raises:
        ValueError: If maxvalue is less than 1.
    """
    if maxvalue < 1:
        raise ValueError("maxvalue must be at least 1")
    return secrets.randbelow(maxvalue)


def randint(maxvalue: int) -> int:
    """Return a random integer in the range [1, maxvalue].

    Args:
        maxvalue: The inclusive upper bound. Must be at least 1.

    Returns:
        A random integer x where 1 <= x <= maxvalue.

    Raises:
        ValueError: If maxvalue is less than 1.
    """
    if maxvalue < 1:
        raise ValueError("maxvalue must be at least 1")
    return read_random_int(maxvalue) + 1
