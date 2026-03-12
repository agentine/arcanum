"""RSA key classes and key generation.

Implements PublicKey, PrivateKey, and newkeys() with PKCS#1 DER/PEM
serialization. DER ASN.1 encoding is done manually using only INTEGER
and SEQUENCE tags (no external dependencies).
"""

from __future__ import annotations

from arcanum import common, pem, prime, randnum

# ---------------------------------------------------------------------------
# ASN.1 DER encoding helpers (INTEGER + SEQUENCE only)
# ---------------------------------------------------------------------------

_TAG_INTEGER = 0x02
_TAG_SEQUENCE = 0x30


def _encode_der_length(length: int) -> bytes:
    """Encode a DER length field."""
    if length < 0x80:
        return bytes([length])
    # Long form
    length_bytes = length.to_bytes((length.bit_length() + 7) // 8, byteorder="big")
    return bytes([0x80 | len(length_bytes)]) + length_bytes


def _encode_der_integer(value: int) -> bytes:
    """Encode an integer as a DER INTEGER."""
    if value == 0:
        payload = b"\x00"
    elif value > 0:
        payload = value.to_bytes((value.bit_length() + 7) // 8, byteorder="big")
        # If the high bit is set, prepend a zero byte
        if payload[0] & 0x80:
            payload = b"\x00" + payload
    else:
        raise ValueError("Negative integers not supported")
    return bytes([_TAG_INTEGER]) + _encode_der_length(len(payload)) + payload


def _encode_der_sequence(contents: bytes) -> bytes:
    """Encode contents as a DER SEQUENCE."""
    return bytes([_TAG_SEQUENCE]) + _encode_der_length(len(contents)) + contents


def _decode_der_length(data: bytes, offset: int) -> tuple[int, int]:
    """Decode a DER length field, returning (length, new_offset)."""
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    num_bytes = first & 0x7F
    if num_bytes == 0:
        raise ValueError("Indefinite length not supported")
    length = int.from_bytes(data[offset + 1 : offset + 1 + num_bytes], byteorder="big")
    return length, offset + 1 + num_bytes


def _decode_der_integer(data: bytes, offset: int) -> tuple[int, int]:
    """Decode a DER INTEGER, returning (value, new_offset)."""
    if data[offset] != _TAG_INTEGER:
        raise ValueError(f"Expected INTEGER tag (0x02), got 0x{data[offset]:02x}")
    length, offset = _decode_der_length(data, offset + 1)
    value_bytes = data[offset : offset + length]
    value = int.from_bytes(value_bytes, byteorder="big", signed=True)
    if value < 0:
        raise ValueError("Negative integer in RSA key")
    return value, offset + length


def _decode_der_sequence(data: bytes, offset: int = 0) -> tuple[bytes, int]:
    """Decode a DER SEQUENCE, returning (contents, new_offset)."""
    if data[offset] != _TAG_SEQUENCE:
        raise ValueError(f"Expected SEQUENCE tag (0x30), got 0x{data[offset]:02x}")
    length, offset = _decode_der_length(data, offset + 1)
    return data[offset : offset + length], offset + length


# ---------------------------------------------------------------------------
# OID for rsaEncryption: 1.2.840.113549.1.1.1
# ---------------------------------------------------------------------------
_OID_RSA_ENCRYPTION = bytes(
    [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
)

# NULL parameter
_DER_NULL = bytes([0x05, 0x00])


# ---------------------------------------------------------------------------
# Key classes
# ---------------------------------------------------------------------------


class AbstractKey:
    """Base class for RSA keys."""

    __slots__ = ("n", "e")

    def __init__(self, n: int, e: int) -> None:
        self.n = n
        self.e = e

    def _blind(self, message: int) -> tuple[int, int]:
        """Blind a message for RSA blinding.

        Returns (blinded_message, unblinding_factor).
        """
        blind_r = randnum.randint(self.n - 1)
        blinded = (message * pow(blind_r, self.e, self.n)) % self.n
        return blinded, blind_r

    def _unblind(self, blinded_result: int, blind_r: int) -> int:
        """Unblind an RSA result."""
        r_inv = pow(blind_r, -1, self.n)
        return (blinded_result * r_inv) % self.n


class PublicKey(AbstractKey):
    """RSA public key.

    Attributes:
        n: The modulus.
        e: The public exponent.
    """

    __slots__ = ()

    def __repr__(self) -> str:
        return f"PublicKey({self.n}, {self.e})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PublicKey):
            return NotImplemented
        return self.n == other.n and self.e == other.e

    def __hash__(self) -> int:
        return hash((self.n, self.e))

    def _save_pkcs1_der(self) -> bytes:
        """Serialize to PKCS#1 DER format (RSAPublicKey)."""
        contents = _encode_der_integer(self.n) + _encode_der_integer(self.e)
        return _encode_der_sequence(contents)

    def save_pkcs1(self, format: str = "PEM") -> bytes:
        """Serialize the public key to PKCS#1 format.

        Args:
            format: ``"PEM"`` or ``"DER"``.

        Returns:
            The serialized key bytes.
        """
        der = self._save_pkcs1_der()
        if format == "DER":
            return der
        return pem.save_pem(der, "RSA PUBLIC KEY")

    @classmethod
    def _load_pkcs1_der(cls, keyfile: bytes) -> PublicKey:
        """Load a PKCS#1 DER-encoded public key (RSAPublicKey)."""
        seq_data, _ = _decode_der_sequence(keyfile)
        offset = 0
        n, offset = _decode_der_integer(seq_data, offset)
        e, offset = _decode_der_integer(seq_data, offset)
        return cls(n=n, e=e)

    @classmethod
    def load_pkcs1(cls, keyfile: bytes, format: str = "PEM") -> PublicKey:
        """Load a PKCS#1 public key.

        Args:
            keyfile: The key data.
            format: ``"PEM"`` or ``"DER"``.

        Returns:
            The loaded PublicKey.
        """
        if format == "DER":
            return cls._load_pkcs1_der(keyfile)
        marker, der_bytes = pem.load_pem(keyfile)
        if marker != "RSA PUBLIC KEY":
            raise ValueError(f"Expected 'RSA PUBLIC KEY' marker, got '{marker}'")
        return cls._load_pkcs1_der(der_bytes)

    @classmethod
    def load_pkcs1_openssl_der(cls, keyfile: bytes) -> PublicKey:
        """Load an OpenSSL DER-encoded public key (SubjectPublicKeyInfo).

        This wraps PKCS#1 RSAPublicKey inside a SubjectPublicKeyInfo
        SEQUENCE with an AlgorithmIdentifier.
        """
        # Outer SEQUENCE
        outer_data, _ = _decode_der_sequence(keyfile)
        offset = 0

        # AlgorithmIdentifier SEQUENCE — skip it
        if outer_data[offset] != _TAG_SEQUENCE:
            raise ValueError("Expected AlgorithmIdentifier SEQUENCE")
        _alg_data, offset = _decode_der_sequence(outer_data, offset)

        # BIT STRING containing the RSAPublicKey
        if outer_data[offset] != 0x03:
            raise ValueError("Expected BIT STRING tag")
        bs_length, offset = _decode_der_length(outer_data, offset + 1)
        # First byte of BIT STRING is the number of unused bits (should be 0)
        _unused_bits = outer_data[offset]
        rsa_pubkey_der = outer_data[offset + 1 : offset + bs_length]

        return cls._load_pkcs1_der(rsa_pubkey_der)

    @classmethod
    def load_pkcs1_openssl_pem(cls, keyfile: bytes) -> PublicKey:
        """Load an OpenSSL PEM-encoded public key (SubjectPublicKeyInfo)."""
        marker, der_bytes = pem.load_pem(keyfile)
        if marker != "PUBLIC KEY":
            raise ValueError(f"Expected 'PUBLIC KEY' marker, got '{marker}'")
        return cls.load_pkcs1_openssl_der(der_bytes)


class PrivateKey(AbstractKey):
    """RSA private key.

    Attributes:
        n: The modulus.
        e: The public exponent.
        d: The private exponent.
        p: The first prime factor.
        q: The second prime factor.
        dp: d mod (p - 1) (precomputed for CRT).
        dq: d mod (q - 1) (precomputed for CRT).
        q_inv: q^(-1) mod p (precomputed for CRT).
    """

    __slots__ = ("d", "p", "q", "dp", "dq", "q_inv")

    def __init__(self, n: int, e: int, d: int, p: int, q: int) -> None:
        super().__init__(n, e)
        self.d = d
        self.p = p
        self.q = q
        # CRT precomputation
        self.dp = d % (p - 1)
        self.dq = d % (q - 1)
        self.q_inv = pow(q, -1, p)

    def __repr__(self) -> str:
        return f"PrivateKey({self.n}, {self.e}, {self.d}, {self.p}, {self.q})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PrivateKey):
            return NotImplemented
        return (
            self.n == other.n
            and self.e == other.e
            and self.d == other.d
            and self.p == other.p
            and self.q == other.q
        )

    def __hash__(self) -> int:
        return hash((self.n, self.e, self.d, self.p, self.q))

    def _raw_decrypt_crt(self, encrypted: int) -> int:
        """Decrypt using the Chinese Remainder Theorem for speed."""
        m1 = pow(encrypted, self.dp, self.p)
        m2 = pow(encrypted, self.dq, self.q)
        h = (self.q_inv * (m1 - m2)) % self.p
        return m2 + h * self.q

    def blinded_decrypt(self, encrypted: int) -> int:
        """Decrypt a message using RSA blinding to mitigate timing attacks.

        Args:
            encrypted: The encrypted message as an integer.

        Returns:
            The decrypted message as an integer.
        """
        blinded, blind_r = self._blind(encrypted)
        decrypted = self._raw_decrypt_crt(blinded)
        return self._unblind(decrypted, blind_r)

    def blinded_encrypt(self, message: int) -> int:
        """Sign/encrypt a message using RSA blinding.

        This is used for signing operations where the private key is used
        to "encrypt" (sign) data.

        Args:
            message: The message as an integer.

        Returns:
            The signed/encrypted message as an integer.
        """
        blinded, blind_r = self._blind(message)
        encrypted = self._raw_decrypt_crt(blinded)
        return self._unblind(encrypted, blind_r)

    def _save_pkcs1_der(self) -> bytes:
        """Serialize to PKCS#1 DER format (RSAPrivateKey)."""
        contents = (
            _encode_der_integer(0)  # version
            + _encode_der_integer(self.n)
            + _encode_der_integer(self.e)
            + _encode_der_integer(self.d)
            + _encode_der_integer(self.p)
            + _encode_der_integer(self.q)
            + _encode_der_integer(self.dp)
            + _encode_der_integer(self.dq)
            + _encode_der_integer(self.q_inv)
        )
        return _encode_der_sequence(contents)

    def save_pkcs1(self, format: str = "PEM") -> bytes:
        """Serialize the private key to PKCS#1 format.

        Args:
            format: ``"PEM"`` or ``"DER"``.

        Returns:
            The serialized key bytes.
        """
        der = self._save_pkcs1_der()
        if format == "DER":
            return der
        return pem.save_pem(der, "RSA PRIVATE KEY")

    @classmethod
    def _load_pkcs1_der(cls, keyfile: bytes) -> PrivateKey:
        """Load a PKCS#1 DER-encoded private key (RSAPrivateKey)."""
        seq_data, _ = _decode_der_sequence(keyfile)
        offset = 0

        version, offset = _decode_der_integer(seq_data, offset)
        if version != 0:
            raise ValueError(f"Unsupported RSAPrivateKey version: {version}")

        n, offset = _decode_der_integer(seq_data, offset)
        e, offset = _decode_der_integer(seq_data, offset)
        d, offset = _decode_der_integer(seq_data, offset)
        p, offset = _decode_der_integer(seq_data, offset)
        q, offset = _decode_der_integer(seq_data, offset)
        # dp, dq, q_inv are in the DER but we recompute them
        _dp, offset = _decode_der_integer(seq_data, offset)
        _dq, offset = _decode_der_integer(seq_data, offset)
        _q_inv, offset = _decode_der_integer(seq_data, offset)

        return cls(n=n, e=e, d=d, p=p, q=q)

    @classmethod
    def load_pkcs1(cls, keyfile: bytes, format: str = "PEM") -> PrivateKey:
        """Load a PKCS#1 private key.

        Args:
            keyfile: The key data.
            format: ``"PEM"`` or ``"DER"``.

        Returns:
            The loaded PrivateKey.
        """
        if format == "DER":
            return cls._load_pkcs1_der(keyfile)
        marker, der_bytes = pem.load_pem(keyfile)
        if marker != "RSA PRIVATE KEY":
            raise ValueError(f"Expected 'RSA PRIVATE KEY' marker, got '{marker}'")
        return cls._load_pkcs1_der(der_bytes)

    # ------------------------------------------------------------------
    # PKCS#8 (PrivateKeyInfo) serialization
    # ------------------------------------------------------------------

    def _save_pkcs8_der(self) -> bytes:
        """Serialize to PKCS#8 DER format (PrivateKeyInfo).

        PrivateKeyInfo ::= SEQUENCE {
            version             INTEGER (0),
            privateKeyAlgorithm AlgorithmIdentifier,
            privateKey          OCTET STRING (contains PKCS#1 RSAPrivateKey)
        }
        """
        pkcs1_der = self._save_pkcs1_der()

        # AlgorithmIdentifier: SEQUENCE { OID rsaEncryption, NULL }
        alg_id = _encode_der_sequence(_OID_RSA_ENCRYPTION + _DER_NULL)

        # OCTET STRING wrapping the PKCS#1 key
        octet_string = bytes([0x04]) + _encode_der_length(len(pkcs1_der)) + pkcs1_der

        contents = (
            _encode_der_integer(0)  # version
            + alg_id
            + octet_string
        )
        return _encode_der_sequence(contents)

    def save_pkcs8(self, format: str = "PEM") -> bytes:
        """Serialize the private key to PKCS#8 format.

        Args:
            format: ``"PEM"`` or ``"DER"``.

        Returns:
            The serialized key bytes.
        """
        der = self._save_pkcs8_der()
        if format == "DER":
            return der
        return pem.save_pem(der, "PRIVATE KEY")

    @classmethod
    def _load_pkcs8_der(cls, keyfile: bytes) -> PrivateKey:
        """Load a PKCS#8 DER-encoded private key (PrivateKeyInfo)."""
        outer_data, _ = _decode_der_sequence(keyfile)
        offset = 0

        # version INTEGER (must be 0)
        version, offset = _decode_der_integer(outer_data, offset)
        if version != 0:
            raise ValueError(f"Unsupported PKCS#8 version: {version}")

        # AlgorithmIdentifier SEQUENCE — skip it
        if outer_data[offset] != _TAG_SEQUENCE:
            raise ValueError("Expected AlgorithmIdentifier SEQUENCE")
        _alg_data, offset = _decode_der_sequence(outer_data, offset)

        # OCTET STRING containing the PKCS#1 RSAPrivateKey
        if outer_data[offset] != 0x04:
            raise ValueError("Expected OCTET STRING tag")
        octet_len, offset = _decode_der_length(outer_data, offset + 1)
        pkcs1_der = outer_data[offset : offset + octet_len]

        return cls._load_pkcs1_der(pkcs1_der)

    @classmethod
    def load_pkcs8(cls, keyfile: bytes, format: str = "PEM") -> PrivateKey:
        """Load a PKCS#8 private key.

        Args:
            keyfile: The key data.
            format: ``"PEM"`` or ``"DER"``.

        Returns:
            The loaded PrivateKey.
        """
        if format == "DER":
            return cls._load_pkcs8_der(keyfile)
        marker, der_bytes = pem.load_pem(keyfile)
        if marker != "PRIVATE KEY":
            raise ValueError(f"Expected 'PRIVATE KEY' marker, got '{marker}'")
        return cls._load_pkcs8_der(der_bytes)


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------


def _find_p_q(
    nbits: int,
    accurate: bool = False,
    exponent: int = 65537,
) -> tuple[int, int]:
    """Find two primes p and q such that p * q has exactly nbits bits.

    Args:
        nbits: Target bit size for n = p * q.
        accurate: If True, ensure n has exactly nbits bits.
        exponent: The public exponent (must be coprime with (p-1)(q-1)).

    Returns:
        A tuple (p, q) with p > q.
    """
    shift = nbits // 2
    pbits = nbits - shift
    qbits = shift

    while True:
        p = prime.getprime(pbits)
        q = prime.getprime(qbits)

        # Ensure p != q
        if p == q:
            continue

        # Ensure p > q (convention)
        if p < q:
            p, q = q, p

        n = p * q

        # Check that n has the right number of bits
        if accurate and common.bit_size(n) != nbits:
            continue

        # If not accurate mode, just check it's large enough
        if not accurate and common.bit_size(n) < nbits:
            continue

        # Ensure e is coprime with phi(n)
        phi_n = (p - 1) * (q - 1)
        if not prime.are_relatively_prime(exponent, phi_n):
            continue

        return p, q


def _compute_d(e: int, phi_n: int) -> int:
    """Compute the private exponent d = e^(-1) mod phi_n."""
    return pow(e, -1, phi_n)


def newkeys(
    nbits: int,
    accurate: bool = False,
    poolsize: int = 1,
    exponent: int = 65537,
) -> tuple[PublicKey, PrivateKey]:
    """Generate a new RSA key pair.

    Args:
        nbits: The number of bits for the modulus *n*. Must be >= 16.
        accurate: If True, ensure the modulus has exactly *nbits* bits.
            This may take longer but guarantees a specific key size.
        poolsize: Number of parallel processes for prime generation.
            Currently ignored (reserved for future multiprocessing support).
        exponent: The public exponent. Default is 65537.

    Returns:
        A tuple of ``(PublicKey, PrivateKey)``.

    Raises:
        ValueError: If nbits is too small.
    """
    if nbits < 16:
        raise ValueError("Key size must be at least 16 bits")

    if poolsize > 1:
        from arcanum.parallel import _find_p_q_parallel
        p, q = _find_p_q_parallel(nbits, poolsize, accurate=accurate, exponent=exponent)
    else:
        p, q = _find_p_q(nbits, accurate=accurate, exponent=exponent)
    n = p * q
    phi_n = (p - 1) * (q - 1)

    # Verify the relationship: lcm approach uses phi, but standard RSA
    # uses Euler's totient. Both work; we use phi_n = (p-1)(q-1).
    d = _compute_d(exponent, phi_n)

    # Verify: e * d ≡ 1 (mod phi_n)
    assert (exponent * d) % phi_n == 1

    return (
        PublicKey(n=n, e=exponent),
        PrivateKey(n=n, e=exponent, d=d, p=p, q=q),
    )
