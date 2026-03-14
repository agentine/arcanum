"""OAEP (PKCS#1 v2.1) encryption and decryption.

Implements RSAES-OAEP as specified in RFC 8017, Section 7.1.
Uses SHA-256 as the default hash function and MGF1 for mask generation.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from ciphertrust import common, transform
from ciphertrust.key import PrivateKey, PublicKey

# ---------------------------------------------------------------------------
# MGF1 mask generation function (RFC 8017, Appendix B.2.1)
# ---------------------------------------------------------------------------


def _mgf1(seed: bytes, length: int, hash_name: str = "sha256") -> bytes:
    """Mask Generation Function 1 (MGF1).

    Args:
        seed: The seed from which the mask is generated.
        length: The desired length of the mask in bytes.
        hash_name: Hash algorithm name (default ``"sha256"``).

    Returns:
        The mask bytes of the specified length.
    """
    h_len = hashlib.new(hash_name).digest_size
    if length > (2**32) * h_len:
        raise ValueError("Mask too long")

    result = b""
    for counter in range((length + h_len - 1) // h_len):
        c = counter.to_bytes(4, byteorder="big")
        result += hashlib.new(hash_name, seed + c).digest()

    return result[:length]


# ---------------------------------------------------------------------------
# OAEP Encrypt / Decrypt
# ---------------------------------------------------------------------------


def encrypt(
    message: bytes,
    pub_key: PublicKey,
    hash_method: str = "SHA-256",
    label: bytes = b"",
) -> bytes:
    """Encrypt a message using RSAES-OAEP (PKCS#1 v2.1).

    Args:
        message: The plaintext message to encrypt.
        pub_key: The RSA public key.
        hash_method: Hash algorithm (default ``"SHA-256"``).
        label: Optional label (default empty).

    Returns:
        The encrypted message bytes.

    Raises:
        ValueError: If the message is too long for the key size.
    """
    hash_name = hash_method.lower().replace("-", "")
    h_len = hashlib.new(hash_name).digest_size
    k = common.byte_size(pub_key.n)  # key byte length

    # Step 1: Length check
    max_msg_len = k - 2 * h_len - 2
    if len(message) > max_msg_len:
        raise ValueError(
            f"Message too long: {len(message)} bytes, max {max_msg_len} for {k * 8}-bit key"
        )

    # Step 2: EME-OAEP encoding
    l_hash = hashlib.new(hash_name, label).digest()
    ps = b"\x00" * (k - len(message) - 2 * h_len - 2)
    db = l_hash + ps + b"\x01" + message
    seed = secrets.token_bytes(h_len)

    db_mask = _mgf1(seed, k - h_len - 1, hash_name)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))

    seed_mask = _mgf1(masked_db, h_len, hash_name)
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))

    em = b"\x00" + masked_seed + masked_db

    # Step 3: RSA encryption
    m = transform.bytes_to_int(em)
    c = pow(m, pub_key.e, pub_key.n)
    return transform.int_to_bytes(c, k)


def decrypt(
    crypto: bytes,
    priv_key: PrivateKey,
    hash_method: str = "SHA-256",
    label: bytes = b"",
) -> bytes:
    """Decrypt a message using RSAES-OAEP (PKCS#1 v2.1).

    Args:
        crypto: The ciphertext to decrypt.
        priv_key: The RSA private key.
        hash_method: Hash algorithm (default ``"SHA-256"``).
        label: Optional label (default empty).

    Returns:
        The decrypted plaintext bytes.

    Raises:
        DecryptionError: If decryption fails (constant-time failure to prevent oracle attacks).
    """
    from ciphertrust.pkcs1 import DecryptionError

    hash_name = hash_method.lower().replace("-", "")
    h_len = hashlib.new(hash_name).digest_size
    k = common.byte_size(priv_key.n)

    # Step 1: Length check
    if len(crypto) != k or k < 2 * h_len + 2:
        raise DecryptionError("Decryption failed")

    # Step 2: RSA decryption (blinded)
    c = transform.bytes_to_int(crypto)
    m = priv_key.blinded_decrypt(c)
    em = transform.int_to_bytes(m, k)

    # Step 3: EME-OAEP decoding
    # Process everything unconditionally for constant-time behavior.
    y = em[0]
    masked_seed = em[1 : 1 + h_len]
    masked_db = em[1 + h_len :]

    seed_mask = _mgf1(masked_db, h_len, hash_name)
    seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))

    db_mask = _mgf1(seed, k - h_len - 1, hash_name)
    db = bytes(a ^ b for a, b in zip(masked_db, db_mask))

    l_hash = hashlib.new(hash_name, label).digest()
    l_hash_prime = db[:h_len]

    # Check Y == 0 and lHash' == lHash (constant-time).
    valid = 1
    valid &= 1 if y == 0 else 0
    valid &= 1 if hmac.compare_digest(l_hash_prime, l_hash) else 0

    # Find the 0x01 separator.
    separator_idx = -1
    for i in range(h_len, len(db)):
        if db[i] == 0x01 and separator_idx < 0:
            separator_idx = i
        elif db[i] != 0x00 and separator_idx < 0:
            valid = 0

    if separator_idx < 0:
        valid = 0

    if not valid:
        raise DecryptionError("Decryption failed")

    return db[separator_idx + 1 :]
