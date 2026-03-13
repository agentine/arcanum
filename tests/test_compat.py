"""Compatibility tests — verify arcanum works as a drop-in for python-rsa.

Tests key generation, serialization round-trips, encrypt/decrypt,
sign/verify, OAEP, and the compat shim import.
"""

from __future__ import annotations

import arcanum
from arcanum.compat import (
    PublicKey,
    PrivateKey,
    newkeys,
    encrypt,
    decrypt,
    sign,
    verify,
)


# 512-bit key for basic tests (fast), 1024-bit for OAEP and large hashes
_PUB: arcanum.PublicKey
_PRIV: arcanum.PrivateKey
_PUB, _PRIV = arcanum.newkeys(512)

_PUB_1024: arcanum.PublicKey
_PRIV_1024: arcanum.PrivateKey
_PUB_1024, _PRIV_1024 = arcanum.newkeys(1024)


class TestCompatImport:
    """The compat shim re-exports the full public API."""

    def test_newkeys(self) -> None:
        pub, priv = newkeys(512)
        assert isinstance(pub, PublicKey)
        assert isinstance(priv, PrivateKey)

    def test_encrypt_decrypt(self) -> None:
        pub, priv = newkeys(512)
        ct = encrypt(b"hello", pub)
        assert decrypt(ct, priv) == b"hello"

    def test_sign_verify(self) -> None:
        pub, priv = newkeys(512)
        sig = sign(b"data", priv, "SHA-256")
        assert verify(b"data", sig, pub) == "SHA-256"


class TestKeySerializationRoundTrip:
    """Keys survive PEM and DER round-trips."""

    def test_public_key_pem_roundtrip(self) -> None:
        pem = _PUB.save_pkcs1("PEM")
        pub2 = arcanum.PublicKey.load_pkcs1(pem)
        assert pub2.n == _PUB.n
        assert pub2.e == _PUB.e

    def test_public_key_der_roundtrip(self) -> None:
        der = _PUB.save_pkcs1("DER")
        pub2 = arcanum.PublicKey.load_pkcs1(der, "DER")
        assert pub2.n == _PUB.n

    def test_private_key_pem_roundtrip(self) -> None:
        pem = _PRIV.save_pkcs1("PEM")
        priv2 = arcanum.PrivateKey.load_pkcs1(pem)
        assert priv2.n == _PRIV.n
        assert priv2.d == _PRIV.d

    def test_private_key_der_roundtrip(self) -> None:
        der = _PRIV.save_pkcs1("DER")
        priv2 = arcanum.PrivateKey.load_pkcs1(der, "DER")
        assert priv2.n == _PRIV.n

    def test_pkcs8_pem_roundtrip(self) -> None:
        pem = _PRIV.save_pkcs8("PEM")
        priv2 = arcanum.PrivateKey.load_pkcs8(pem)
        assert priv2.n == _PRIV.n
        assert priv2.d == _PRIV.d

    def test_pkcs8_der_roundtrip(self) -> None:
        der = _PRIV.save_pkcs8("DER")
        priv2 = arcanum.PrivateKey.load_pkcs8(der, "DER")
        assert priv2.n == _PRIV.n


class TestCrossKeyEncryption:
    """Keys from one format can decrypt ciphertext from another."""

    def test_pem_key_decrypts_original(self) -> None:
        ct = arcanum.encrypt(b"cross-format", _PUB)
        pem = _PRIV.save_pkcs1("PEM")
        priv2 = arcanum.PrivateKey.load_pkcs1(pem)
        assert arcanum.decrypt(ct, priv2) == b"cross-format"

    def test_pkcs8_key_decrypts_original(self) -> None:
        ct = arcanum.encrypt(b"cross-format", _PUB)
        pkcs8 = _PRIV.save_pkcs8("PEM")
        priv2 = arcanum.PrivateKey.load_pkcs8(pkcs8)
        assert arcanum.decrypt(ct, priv2) == b"cross-format"


class TestCrossKeySignature:
    """Signatures created with one key format verify with another."""

    def test_pem_key_verifies_signature(self) -> None:
        sig = arcanum.sign(b"important", _PRIV, "SHA-256")
        pem = _PUB.save_pkcs1("PEM")
        pub2 = arcanum.PublicKey.load_pkcs1(pem)
        assert arcanum.verify(b"important", sig, pub2) == "SHA-256"

    def test_der_key_verifies_signature(self) -> None:
        sig = arcanum.sign(b"important", _PRIV, "SHA-1")
        der = _PUB.save_pkcs1("DER")
        pub2 = arcanum.PublicKey.load_pkcs1(der, "DER")
        assert arcanum.verify(b"important", sig, pub2) == "SHA-1"


class TestOAEPCompatibility:
    """OAEP encrypt/decrypt works across serialization formats."""

    def test_oaep_roundtrip(self) -> None:
        ct = arcanum.oaep_encrypt(b"oaep", _PUB_1024)
        assert arcanum.oaep_decrypt(ct, _PRIV_1024) == b"oaep"

    def test_oaep_with_deserialized_key(self) -> None:
        ct = arcanum.oaep_encrypt(b"oaep", _PUB_1024)
        pem = _PRIV_1024.save_pkcs8("PEM")
        priv2 = arcanum.PrivateKey.load_pkcs8(pem)
        assert arcanum.oaep_decrypt(ct, priv2) == b"oaep"


class TestMultipleHashAlgorithms:
    """Sign/verify with every supported hash algorithm."""

    def test_sha1(self) -> None:
        sig = arcanum.sign(b"x", _PRIV, "SHA-1")
        assert arcanum.verify(b"x", sig, _PUB) == "SHA-1"

    def test_sha256(self) -> None:
        sig = arcanum.sign(b"x", _PRIV, "SHA-256")
        assert arcanum.verify(b"x", sig, _PUB) == "SHA-256"

    def test_sha384(self) -> None:
        sig = arcanum.sign(b"x", _PRIV_1024, "SHA-384")
        assert arcanum.verify(b"x", sig, _PUB_1024) == "SHA-384"

    def test_sha512(self) -> None:
        sig = arcanum.sign(b"x", _PRIV_1024, "SHA-512")
        assert arcanum.verify(b"x", sig, _PUB_1024) == "SHA-512"

    def test_md5(self) -> None:
        sig = arcanum.sign(b"x", _PRIV, "MD5")
        assert arcanum.verify(b"x", sig, _PUB) == "MD5"


class TestAPISurface:
    """Verify all expected names are importable from arcanum."""

    def test_all_exports(self) -> None:
        expected = {
            "PublicKey", "PrivateKey", "newkeys",
            "encrypt", "decrypt",
            "sign", "sign_hash", "verify", "find_signature_hash", "compute_hash",
            "oaep_encrypt", "oaep_decrypt",
            "CryptoError", "DecryptionError", "VerificationError",
            "bit_size", "byte_size",
            "bytes_to_int", "int_to_bytes",
            "load_pem", "save_pem",
            "HASH_ASN1", "HASH_METHODS",
        }
        assert expected.issubset(set(arcanum.__all__))

    def test_version(self) -> None:
        assert arcanum.__version__ == "0.1.0"
