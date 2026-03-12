"""Tests for arcanum.transform — byte/integer conversions."""

import pytest

from arcanum.transform import bytes_to_int, int_to_bytes


class TestBytesToInt:
    def test_zero(self) -> None:
        assert bytes_to_int(b"\x00") == 0

    def test_single_byte(self) -> None:
        assert bytes_to_int(b"\xff") == 255

    def test_two_bytes(self) -> None:
        assert bytes_to_int(b"\x01\x00") == 256

    def test_known_vector(self) -> None:
        assert bytes_to_int(b"\x01\x02\x03") == 0x010203

    def test_empty_bytes(self) -> None:
        assert bytes_to_int(b"") == 0

    def test_large_number(self) -> None:
        # 2^64
        data = b"\x01" + b"\x00" * 8
        assert bytes_to_int(data) == 2**64

    def test_leading_zeros(self) -> None:
        assert bytes_to_int(b"\x00\x00\x01") == 1


class TestIntToBytes:
    def test_zero(self) -> None:
        assert int_to_bytes(0) == b"\x00"

    def test_single_byte(self) -> None:
        assert int_to_bytes(255) == b"\xff"

    def test_256(self) -> None:
        assert int_to_bytes(256) == b"\x01\x00"

    def test_known_vector(self) -> None:
        assert int_to_bytes(0x010203) == b"\x01\x02\x03"

    def test_fill_size(self) -> None:
        result = int_to_bytes(1, fill_size=4)
        assert result == b"\x00\x00\x00\x01"
        assert len(result) == 4

    def test_fill_size_exact(self) -> None:
        result = int_to_bytes(256, fill_size=2)
        assert result == b"\x01\x00"

    def test_fill_size_overflow(self) -> None:
        with pytest.raises(OverflowError):
            int_to_bytes(256, fill_size=1)

    def test_negative_raises(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            int_to_bytes(-1)

    def test_large_number(self) -> None:
        result = int_to_bytes(2**64)
        assert len(result) == 9
        assert result[0] == 1
        assert result[1:] == b"\x00" * 8


class TestRoundTrip:
    @pytest.mark.parametrize("value", [0, 1, 127, 128, 255, 256, 65535, 2**128 - 1])
    def test_round_trip(self, value: int) -> None:
        """Converting int -> bytes -> int should return the original value."""
        assert bytes_to_int(int_to_bytes(value)) == value

    @pytest.mark.parametrize(
        "data",
        [b"\x00", b"\x01", b"\xff", b"\x01\x00", b"\xde\xad\xbe\xef"],
    )
    def test_bytes_round_trip(self, data: bytes) -> None:
        """Converting bytes -> int -> bytes should preserve the value.

        Note: leading zeros may not be preserved unless fill_size is used.
        """
        value = bytes_to_int(data)
        result = int_to_bytes(value, fill_size=len(data))
        assert result == data

    def test_fill_size_round_trip(self) -> None:
        """Round-trip with explicit fill_size."""
        for fill in [1, 2, 4, 8, 16, 32, 64]:
            value = bytes_to_int(b"\x01" + b"\x00" * (fill - 1))
            result = int_to_bytes(value, fill_size=fill)
            assert len(result) == fill
            assert bytes_to_int(result) == value
