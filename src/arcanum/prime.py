"""Prime number generation and primality testing.

Uses Miller-Rabin primality testing with trial division for efficiency.
All randomness comes from the ``secrets`` module via :mod:`arcanum.randnum`.
"""

import math

from arcanum import randnum

# First 2000 primes for trial division (sieved at import time).
_SMALL_PRIMES: list[int] = []


def _sieve_small_primes() -> list[int]:
    """Compute the first 2000 primes using a simple sieve."""
    primes: list[int] = []
    candidate = 2
    while len(primes) < 2000:
        is_prime = True
        limit = int(math.isqrt(candidate)) + 1
        for p in primes:
            if p > limit:
                break
            if candidate % p == 0:
                is_prime = False
                break
        if is_prime:
            primes.append(candidate)
        candidate += 1
    return primes


_SMALL_PRIMES = _sieve_small_primes()


def miller_rabin_primality_test(n: int, k: int = 20) -> bool:
    """Perform the Miller-Rabin primality test.

    Args:
        n: The number to test. Must be >= 2.
        k: The number of rounds (witnesses) to test. More rounds give
           higher confidence. Default is 20 (error probability <= 2^-40).

    Returns:
        True if *n* is probably prime, False if *n* is definitely composite.
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n - 1 as 2^r * d where d is odd
    r = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        r += 1

    # Witness loop
    for _ in range(k):
        # Pick a random witness in [2, n - 2]
        a = randnum.read_random_int(n - 3) + 2  # [2, n-2]

        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            # None of the squarings gave n - 1 => composite
            return False

    return True


def is_prime(number: int) -> bool:
    """Test whether a number is prime.

    Combines trial division with the first 2000 primes and Miller-Rabin
    testing (20 rounds) for larger numbers.

    Args:
        number: The number to test.

    Returns:
        True if the number is (probably) prime, False otherwise.
    """
    if number < 2:
        return False

    # Trial division with small primes
    for p in _SMALL_PRIMES:
        if number == p:
            return True
        if number % p == 0:
            return False

    # If we got here, number > largest small prime and passed trial division.
    # Apply Miller-Rabin.
    return miller_rabin_primality_test(number, k=20)


def getprime(nbits: int) -> int:
    """Generate a random prime number with exactly *nbits* bits.

    The returned prime will have its most significant bit set, so it is
    guaranteed to be in the range [2^(nbits-1), 2^nbits - 1].

    Args:
        nbits: The exact number of bits for the prime. Must be >= 2.

    Returns:
        A prime number with exactly nbits bits.

    Raises:
        ValueError: If nbits is less than 2.
    """
    if nbits < 2:
        raise ValueError("nbits must be at least 2")

    while True:
        candidate = randnum.read_random_bits(nbits)
        # Ensure it's odd
        candidate |= 1
        if is_prime(candidate):
            return candidate


def are_relatively_prime(a: int, b: int) -> bool:
    """Test whether two integers are relatively prime (coprime).

    Args:
        a: First integer.
        b: Second integer.

    Returns:
        True if gcd(a, b) == 1.
    """
    return math.gcd(a, b) == 1
