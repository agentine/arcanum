"""Tests for arcanum.prime — primality testing and prime generation."""

import pytest

from arcanum.prime import (
    are_relatively_prime,
    getprime,
    is_prime,
    miller_rabin_primality_test,
)


class TestMillerRabin:
    @pytest.mark.parametrize("p", [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31])
    def test_small_primes(self, p: int) -> None:
        assert miller_rabin_primality_test(p) is True

    @pytest.mark.parametrize("n", [4, 6, 8, 9, 10, 12, 15, 21, 25, 27])
    def test_small_composites(self, n: int) -> None:
        assert miller_rabin_primality_test(n) is False

    def test_large_known_prime(self) -> None:
        # Mersenne prime M_61 = 2^61 - 1
        m61 = 2**61 - 1
        assert miller_rabin_primality_test(m61) is True

    def test_carmichael_number(self) -> None:
        # 561 = 3 * 11 * 17 is the smallest Carmichael number
        assert miller_rabin_primality_test(561) is False

    def test_zero_and_one(self) -> None:
        assert miller_rabin_primality_test(0) is False
        assert miller_rabin_primality_test(1) is False


class TestIsPrime:
    @pytest.mark.parametrize("p", [2, 3, 5, 7, 11, 101, 997, 7919])
    def test_known_primes(self, p: int) -> None:
        assert is_prime(p) is True

    @pytest.mark.parametrize("n", [0, 1, 4, 6, 100, 1000, 7917])
    def test_known_composites(self, n: int) -> None:
        assert is_prime(n) is False

    def test_large_prime(self) -> None:
        # Known large prime
        p = 104729
        assert is_prime(p) is True

    def test_negative(self) -> None:
        assert is_prime(-1) is False

    def test_prime_product(self) -> None:
        # Product of two primes is not prime
        assert is_prime(7 * 11) is False


class TestGetPrime:
    def test_bit_length_512(self) -> None:
        p = getprime(512)
        assert p.bit_length() == 512
        assert is_prime(p) is True

    def test_bit_length_128(self) -> None:
        p = getprime(128)
        assert p.bit_length() == 128
        assert is_prime(p) is True

    def test_bit_length_32(self) -> None:
        p = getprime(32)
        assert p.bit_length() == 32
        assert is_prime(p) is True

    def test_minimum_bits(self) -> None:
        p = getprime(2)
        assert p.bit_length() == 2
        assert is_prime(p) is True

    def test_too_small_raises(self) -> None:
        with pytest.raises(ValueError, match="at least 2"):
            getprime(1)

    def test_is_odd(self) -> None:
        """Generated primes should be odd (except 2, but 2 is 2-bit at most)."""
        for _ in range(5):
            p = getprime(64)
            assert p % 2 == 1


class TestAreRelativelyPrime:
    def test_coprime(self) -> None:
        assert are_relatively_prime(15, 28) is True

    def test_not_coprime(self) -> None:
        assert are_relatively_prime(12, 18) is False

    def test_one(self) -> None:
        assert are_relatively_prime(1, 100) is True

    def test_same_number(self) -> None:
        assert are_relatively_prime(7, 7) is False

    def test_primes(self) -> None:
        assert are_relatively_prime(13, 17) is True

    def test_with_e(self) -> None:
        """Common RSA scenario: e=65537 coprime with phi(n)."""
        # phi(n) for two known primes
        p, q = 61, 53
        phi = (p - 1) * (q - 1)
        assert are_relatively_prime(65537, phi) is True
