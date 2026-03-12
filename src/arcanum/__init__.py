"""Arcanum — a pure-Python RSA library.

Provides RSA key generation, PKCS#1 v1.5 and OAEP (v2.1) encryption/decryption,
signing/verification, and key serialization in PKCS#1/PKCS#8/PEM/DER formats.

Quick start::

    import arcanum

    pub, priv = arcanum.newkeys(2048)
    crypto = arcanum.encrypt(b"hello", pub)
    assert arcanum.decrypt(crypto, priv) == b"hello"
"""

from __future__ import annotations

from arcanum.key import PublicKey, PrivateKey, newkeys
from arcanum.pkcs1 import (
    encrypt,
    decrypt,
    sign,
    sign_hash,
    verify,
    find_signature_hash,
    compute_hash,
    CryptoError,
    DecryptionError,
    VerificationError,
    HASH_ASN1,
    HASH_METHODS,
)
from arcanum.pkcs1_v2 import (
    encrypt as oaep_encrypt,
    decrypt as oaep_decrypt,
)
from arcanum.common import bit_size, byte_size
from arcanum.transform import bytes_to_int, int_to_bytes
from arcanum.pem import load_pem, save_pem

__version__ = "0.1.0"

__all__ = [
    # Key classes and generation
    "PublicKey",
    "PrivateKey",
    "newkeys",
    # PKCS#1 v1.5
    "encrypt",
    "decrypt",
    "sign",
    "sign_hash",
    "verify",
    "find_signature_hash",
    "compute_hash",
    # OAEP (PKCS#1 v2.1)
    "oaep_encrypt",
    "oaep_decrypt",
    # Exceptions
    "CryptoError",
    "DecryptionError",
    "VerificationError",
    # Utilities
    "bit_size",
    "byte_size",
    "bytes_to_int",
    "int_to_bytes",
    "load_pem",
    "save_pem",
    # Constants
    "HASH_ASN1",
    "HASH_METHODS",
]
