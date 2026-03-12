"""Compatibility shim for python-rsa: ``import arcanum as rsa``.

This module re-exports the arcanum public API under the names that
python-rsa uses, allowing existing code to work with minimal changes::

    import arcanum as rsa
    # or
    from arcanum.compat import *

    pub, priv = rsa.newkeys(2048)
    crypto = rsa.encrypt(b"hello", pub)
    message = rsa.decrypt(crypto, priv)
"""

from __future__ import annotations

# Key classes and generation
from arcanum.key import PublicKey, PrivateKey, newkeys  # noqa: F401

# PKCS#1 v1.5 operations
from arcanum.pkcs1 import (  # noqa: F401
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

# OAEP
from arcanum.pkcs1_v2 import (  # noqa: F401
    encrypt as oaep_encrypt,
    decrypt as oaep_decrypt,
)

# Utilities
from arcanum.common import bit_size, byte_size  # noqa: F401
from arcanum.transform import bytes_to_int, int_to_bytes  # noqa: F401
from arcanum.pem import load_pem, save_pem  # noqa: F401

__all__ = [
    "PublicKey",
    "PrivateKey",
    "newkeys",
    "encrypt",
    "decrypt",
    "sign",
    "sign_hash",
    "verify",
    "find_signature_hash",
    "compute_hash",
    "oaep_encrypt",
    "oaep_decrypt",
    "CryptoError",
    "DecryptionError",
    "VerificationError",
    "bit_size",
    "byte_size",
    "bytes_to_int",
    "int_to_bytes",
    "load_pem",
    "save_pem",
    "HASH_ASN1",
    "HASH_METHODS",
]
