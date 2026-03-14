"""Byte-integer transformation utilities.

Big-endian conversions between bytes and arbitrary-precision integers.
"""


def bytes_to_int(data: bytes) -> int:
    """Convert a byte string to an integer (big-endian).

    Args:
        data: The byte string to convert.

    Returns:
        The integer representation of the byte string.
    """
    return int.from_bytes(data, byteorder="big")


def int_to_bytes(number: int, fill_size: int = 0) -> bytes:
    """Convert an integer to a byte string (big-endian).

    Args:
        number: The integer to convert. Must be non-negative.
        fill_size: Minimum number of bytes in the output. If the integer
            requires fewer bytes, the output is left-padded with zero bytes.
            If 0, the output uses the minimum number of bytes needed.

    Returns:
        The byte string representation of the integer.

    Raises:
        ValueError: If the number is negative.
        OverflowError: If the number does not fit in fill_size bytes.
    """
    if number < 0:
        raise ValueError("Number must be non-negative")

    if number == 0:
        raw = b"\x00"
    else:
        byte_count = (number.bit_length() + 7) // 8
        raw = number.to_bytes(byte_count, byteorder="big")

    if fill_size > 0:
        if len(raw) > fill_size:
            raise OverflowError(
                f"Need {len(raw)} bytes for number, but fill_size is {fill_size}"
            )
        raw = raw.rjust(fill_size, b"\x00")

    return raw
