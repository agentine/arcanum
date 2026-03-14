"""Common utility functions.

Provides bit_size and byte_size calculations for integers.
"""


def bit_size(number: int) -> int:
    """Return the number of bits needed to represent the integer.

    Args:
        number: The integer to measure. Must be non-negative.

    Returns:
        The number of bits needed. Returns 0 for the value 0.

    Raises:
        ValueError: If the number is negative.
    """
    if number < 0:
        raise ValueError("Number must be non-negative")
    return number.bit_length()


def byte_size(number: int) -> int:
    """Return the number of bytes needed to represent the integer.

    Args:
        number: The integer to measure. Must be non-negative.

    Returns:
        The number of bytes needed. Returns 1 for the value 0.

    Raises:
        ValueError: If the number is negative.
    """
    if number < 0:
        raise ValueError("Number must be non-negative")
    bit_count = bit_size(number)
    if bit_count == 0:
        return 1
    return (bit_count + 7) // 8
