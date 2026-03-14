"""Low-level modular exponentiation.

Thin wrapper around Python's built-in three-argument ``pow()``.
"""


def fast_pow(base: int, exponent: int, modulus: int) -> int:
    """Compute (base ** exponent) % modulus efficiently.

    Uses Python's built-in modular exponentiation which implements
    a fast binary exponentiation algorithm.

    Args:
        base: The base.
        exponent: The exponent. Must be non-negative.
        modulus: The modulus. Must be positive.

    Returns:
        (base ** exponent) % modulus

    Raises:
        ValueError: If modulus is not positive or exponent is negative.
    """
    if modulus < 1:
        raise ValueError("Modulus must be positive")
    if exponent < 0:
        raise ValueError("Exponent must be non-negative")
    return pow(base, exponent, modulus)
