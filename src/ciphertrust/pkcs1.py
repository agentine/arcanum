"""PKCS#1 v1.5 encryption, decryption, signing, and verification.

Implements the PKCS#1 v1.5 scheme as specified in RFC 8017 (PKCS #1: RSA
Cryptography Specifications Version 2.2).

All private-key operations use RSA blinding to mitigate timing attacks.
Signature verification uses ``hmac.compare_digest()`` for constant-time
hash comparison.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import typing

from ciphertrust import common, transform
from ciphertrust.key import PrivateKey, PublicKey

# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class CryptoError(Exception):
    """Base exception for all cryptographic errors."""


class DecryptionError(CryptoError):
    """Raised when PKCS#1 v1.5 decryption fails.

    This deliberately reveals no information about *why* the decryption
    failed, to avoid padding-oracle attacks.
    """


class VerificationError(CryptoError):
    """Raised when PKCS#1 v1.5 signature verification fails."""


# ---------------------------------------------------------------------------
# Supported hash algorithms
# ---------------------------------------------------------------------------

# DER-encoded DigestInfo prefixes for each hash algorithm (RFC 8017, Section 9.2)
# Each prefix is: SEQUENCE { SEQUENCE { OID, NULL }, OCTET STRING { hash } }
# We store everything up to (but not including) the hash value itself.

HASH_ASN1: dict[str, bytes] = {
    "MD5": bytes(
        [
            0x30,
            0x20,  # SEQUENCE (32 bytes)
            0x30,
            0x0C,  # SEQUENCE (12 bytes)
            0x06,
            0x08,  # OID (8 bytes)
            0x2A,
            0x86,
            0x48,
            0x86,
            0xF7,
            0x0D,
            0x02,
            0x05,  # md5
            0x05,
            0x00,  # NULL
            0x04,
            0x10,  # OCTET STRING (16 bytes)
        ]
    ),
    "SHA-1": bytes(
        [
            0x30,
            0x21,  # SEQUENCE (33 bytes)
            0x30,
            0x09,  # SEQUENCE (9 bytes)
            0x06,
            0x05,  # OID (5 bytes)
            0x2B,
            0x0E,
            0x03,
            0x02,
            0x1A,  # sha1
            0x05,
            0x00,  # NULL
            0x04,
            0x14,  # OCTET STRING (20 bytes)
        ]
    ),
    "SHA-256": bytes(
        [
            0x30,
            0x31,  # SEQUENCE (49 bytes)
            0x30,
            0x0D,  # SEQUENCE (13 bytes)
            0x06,
            0x09,  # OID (9 bytes)
            0x60,
            0x86,
            0x48,
            0x01,
            0x65,
            0x03,
            0x04,
            0x02,
            0x01,  # sha256
            0x05,
            0x00,  # NULL
            0x04,
            0x20,  # OCTET STRING (32 bytes)
        ]
    ),
    "SHA-384": bytes(
        [
            0x30,
            0x41,  # SEQUENCE (65 bytes)
            0x30,
            0x0D,  # SEQUENCE (13 bytes)
            0x06,
            0x09,  # OID (9 bytes)
            0x60,
            0x86,
            0x48,
            0x01,
            0x65,
            0x03,
            0x04,
            0x02,
            0x02,  # sha384
            0x05,
            0x00,  # NULL
            0x04,
            0x30,  # OCTET STRING (48 bytes)
        ]
    ),
    "SHA-512": bytes(
        [
            0x30,
            0x51,  # SEQUENCE (81 bytes)
            0x30,
            0x0D,  # SEQUENCE (13 bytes)
            0x06,
            0x09,  # OID (9 bytes)
            0x60,
            0x86,
            0x48,
            0x01,
            0x65,
            0x03,
            0x04,
            0x02,
            0x03,  # sha512
            0x05,
            0x00,  # NULL
            0x04,
            0x40,  # OCTET STRING (64 bytes)
        ]
    ),
}

# Expected digest sizes in bytes per algorithm.
HASH_LENGTHS: dict[str, int] = {
    "MD5": 16,
    "SHA-1": 20,
    "SHA-256": 32,
    "SHA-384": 48,
    "SHA-512": 64,
}

# Mapping from hash name to hashlib name
HASH_METHODS: dict[str, str] = {
    "MD5": "md5",
    "SHA-1": "sha1",
    "SHA-256": "sha256",
    "SHA-384": "sha384",
    "SHA-512": "sha512",
}


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------


def compute_hash(
    message: bytes | typing.BinaryIO,
    method_name: str,
) -> bytes:
    """Compute a message digest.

    Args:
        message: The message to hash, either as ``bytes`` or as a readable
            binary file-like object.
        method_name: The hash algorithm name. One of ``"MD5"``, ``"SHA-1"``,
            ``"SHA-256"``, ``"SHA-384"``, ``"SHA-512"``.

    Returns:
        The hash digest as bytes.

    Raises:
        ValueError: If the hash algorithm is not supported.
    """
    if method_name not in HASH_METHODS:
        raise ValueError(
            f"Unsupported hash method: {method_name!r}. "
            f"Supported: {', '.join(sorted(HASH_METHODS))}"
        )

    hasher = hashlib.new(HASH_METHODS[method_name])

    if isinstance(message, bytes):
        hasher.update(message)
    else:
        # File-like object: read in chunks
        while True:
            block = message.read(8192)
            if not block:
                break
            hasher.update(block)

    return hasher.digest()


# ---------------------------------------------------------------------------
# PKCS#1 v1.5 padding
# ---------------------------------------------------------------------------


def _pad_for_encryption(message: bytes, target_length: int) -> bytes:
    """Apply PKCS#1 v1.5 type 2 padding for encryption.

    The padded message has the form::

        0x00 0x02 [random non-zero padding bytes] 0x00 [message]

    Args:
        message: The plaintext message to pad.
        target_length: The desired length in bytes (key byte size).

    Returns:
        The padded message.

    Raises:
        OverflowError: If the message is too long for the key size.
    """
    max_msg_length = target_length - 11  # 3 fixed + at least 8 padding
    if len(message) > max_msg_length:
        raise OverflowError(
            f"Message is {len(message)} bytes, maximum is {max_msg_length} "
            f"for a {target_length * 8}-bit key"
        )

    # Generate random non-zero padding bytes
    padding_length = target_length - len(message) - 3
    padding = bytearray()
    while len(padding) < padding_length:
        # Generate more bytes than needed to account for zeros
        new_bytes = secrets.token_bytes(padding_length - len(padding) + 16)
        for b in new_bytes:
            if b != 0 and len(padding) < padding_length:
                padding.append(b)

    return b"\x00\x02" + bytes(padding) + b"\x00" + message


def _pad_for_signing(message: bytes, target_length: int) -> bytes:
    """Apply PKCS#1 v1.5 type 1 padding for signing.

    The padded message has the form::

        0x00 0x01 [0xFF padding bytes] 0x00 [message]

    Args:
        message: The DigestInfo to pad (already includes ASN.1 prefix + hash).
        target_length: The desired length in bytes (key byte size).

    Returns:
        The padded message.

    Raises:
        OverflowError: If the message is too long for the key size.
    """
    max_msg_length = target_length - 11  # 3 fixed + at least 8 padding
    if len(message) > max_msg_length:
        raise OverflowError(
            f"Message is {len(message)} bytes, maximum is {max_msg_length} "
            f"for a {target_length * 8}-bit key"
        )

    padding_length = target_length - len(message) - 3
    padding = b"\xff" * padding_length

    return b"\x00\x01" + padding + b"\x00" + message


# ---------------------------------------------------------------------------
# Encryption / Decryption
# ---------------------------------------------------------------------------


def encrypt(message: bytes, pub_key: PublicKey) -> bytes:
    """Encrypt a message using PKCS#1 v1.5 (type 2 padding).

    Args:
        message: The plaintext to encrypt. Must be short enough for the key
            size (at most ``key_bytes - 11`` bytes).
        pub_key: The recipient's public key.

    Returns:
        The ciphertext as bytes, with the same length as the key modulus.

    Raises:
        OverflowError: If the message is too long for the key.
    """
    keylength = common.byte_size(pub_key.n)
    padded = _pad_for_encryption(message, keylength)

    # Convert to integer, encrypt, convert back
    payload_int = transform.bytes_to_int(padded)
    encrypted_int = pow(payload_int, pub_key.e, pub_key.n)
    return transform.int_to_bytes(encrypted_int, fill_size=keylength)


def decrypt(crypto: bytes, priv_key: PrivateKey) -> bytes:
    """Decrypt a PKCS#1 v1.5 encrypted message.

    Uses RSA blinding for all private-key operations.

    Args:
        crypto: The ciphertext to decrypt.
        priv_key: The recipient's private key.

    Returns:
        The decrypted plaintext.

    Raises:
        DecryptionError: If the ciphertext is invalid or padding is malformed.
    """
    keylength = common.byte_size(priv_key.n)

    # Validate input range per RFC 8017 step 1: ciphertext integer must be in [0, n).
    encrypted_int = transform.bytes_to_int(crypto)
    if encrypted_int >= priv_key.n:
        raise DecryptionError("Decryption failed")
    decrypted_int = priv_key.blinded_decrypt(encrypted_int)
    padded = transform.int_to_bytes(decrypted_int, fill_size=keylength)

    # Verify and strip PKCS#1 v1.5 type 2 padding in constant time.
    # Format: 0x00 0x02 [non-zero padding bytes, >= 8] 0x00 [message]
    #
    # All bytes are processed unconditionally to prevent Bleichenbacher-style
    # padding oracle attacks via timing side channels.
    valid = 1

    # Length check
    if len(padded) != keylength:
        raise DecryptionError("Decryption failed")

    # Header must be 0x00 0x02
    valid &= 1 if padded[0] == 0x00 else 0
    valid &= 1 if padded[1] == 0x02 else 0

    # Scan all bytes to find the first 0x00 separator after position 1.
    # We process every byte unconditionally.
    sep_idx = 0
    found_sep = 0
    for i in range(2, len(padded)):
        is_zero = 1 if padded[i] == 0x00 else 0
        # Record the first separator position (only when not yet found).
        is_first = is_zero & (1 - found_sep)
        sep_idx = sep_idx | (i * is_first)
        found_sep |= is_zero

    # Must have found a separator.
    valid &= found_sep

    # Padding must be at least 8 bytes: separator at index >= 10.
    valid &= 1 if sep_idx >= 10 else 0

    if valid != 1:
        raise DecryptionError("Decryption failed")

    return padded[sep_idx + 1 :]


# ---------------------------------------------------------------------------
# Signing / Verification
# ---------------------------------------------------------------------------


def sign(
    message: bytes,
    priv_key: PrivateKey,
    hash_method: str,
) -> bytes:
    """Sign a message using PKCS#1 v1.5.

    Computes the hash of the message, then signs the DigestInfo structure.
    Uses RSA blinding for the private-key operation.

    Args:
        message: The message to sign.
        priv_key: The signer's private key.
        hash_method: The hash algorithm name (e.g., ``"SHA-256"``).

    Returns:
        The signature as bytes.

    Raises:
        ValueError: If the hash method is not supported.
        OverflowError: If the key is too small for the hash + padding.
    """
    msg_hash = compute_hash(message, hash_method)
    return sign_hash(msg_hash, priv_key, hash_method)


def sign_hash(
    hash_value: bytes,
    priv_key: PrivateKey,
    hash_method: str,
) -> bytes:
    """Sign a pre-computed hash using PKCS#1 v1.5.

    Uses RSA blinding for the private-key operation.

    Args:
        hash_value: The pre-computed hash digest.
        priv_key: The signer's private key.
        hash_method: The hash algorithm name (e.g., ``"SHA-256"``).

    Returns:
        The signature as bytes.

    Raises:
        ValueError: If the hash method is not supported.
        OverflowError: If the key is too small for the hash + padding.
    """
    if hash_method not in HASH_ASN1:
        raise ValueError(
            f"Unsupported hash method: {hash_method!r}. Supported: {', '.join(sorted(HASH_ASN1))}"
        )

    expected_len = HASH_LENGTHS[hash_method]
    if len(hash_value) != expected_len:
        raise ValueError(
            f"Hash length mismatch for {hash_method}: "
            f"expected {expected_len} bytes, got {len(hash_value)}"
        )

    keylength = common.byte_size(priv_key.n)

    # Build DigestInfo: ASN.1 prefix + hash
    digest_info = HASH_ASN1[hash_method] + hash_value

    # Apply type 1 padding
    padded = _pad_for_signing(digest_info, keylength)

    # Sign using blinding
    payload_int = transform.bytes_to_int(padded)
    signed_int = priv_key.blinded_encrypt(payload_int)
    return transform.int_to_bytes(signed_int, fill_size=keylength)


def verify(
    message: bytes,
    signature: bytes,
    pub_key: PublicKey,
) -> str:
    """Verify a PKCS#1 v1.5 signature.

    Uses ``hmac.compare_digest()`` for constant-time hash comparison.

    Args:
        message: The original message.
        signature: The signature to verify.
        pub_key: The signer's public key.

    Returns:
        The name of the hash algorithm used in the signature.

    Raises:
        VerificationError: If the signature is invalid.
    """
    keylength = common.byte_size(pub_key.n)

    # Validate input range per RFC 8017: signature integer must be in [0, n).
    sig_int = transform.bytes_to_int(signature)
    if sig_int >= pub_key.n:
        raise VerificationError("Verification failed")

    # "Decrypt" the signature with the public key
    decrypted_int = pow(sig_int, pub_key.e, pub_key.n)
    padded = transform.int_to_bytes(decrypted_int, fill_size=keylength)

    # Verify and strip type 1 padding
    if padded[0:2] != b"\x00\x01":
        raise VerificationError("Verification failed")

    # Find the 0x00 separator
    try:
        sep_idx = padded.index(b"\x00", 2)
    except ValueError:
        raise VerificationError("Verification failed") from None

    # Check that the padding is all 0xFF bytes
    if padded[2:sep_idx] != b"\xff" * (sep_idx - 2):
        raise VerificationError("Verification failed")

    # Padding must be at least 8 bytes
    if sep_idx < 10:
        raise VerificationError("Verification failed")

    digest_info = padded[sep_idx + 1 :]

    # Try each hash algorithm to find which one matches
    for hash_name, asn1_prefix in HASH_ASN1.items():
        if not digest_info.startswith(asn1_prefix):
            continue

        hash_from_sig = digest_info[len(asn1_prefix) :]
        msg_hash = compute_hash(message, hash_name)

        # Constant-time comparison
        if hmac.compare_digest(hash_from_sig, msg_hash):
            return hash_name

    raise VerificationError("Verification failed")


def find_signature_hash(
    signature: bytes,
    pub_key: PublicKey,
) -> str:
    """Find the hash algorithm used in a signature.

    This does NOT verify the signature — it only determines which hash
    algorithm was used to create it.

    Args:
        signature: The signature to inspect.
        pub_key: The signer's public key.

    Returns:
        The name of the hash algorithm (e.g., ``"SHA-256"``).

    Raises:
        VerificationError: If the signature format is invalid or the hash
            algorithm cannot be determined.
    """
    keylength = common.byte_size(pub_key.n)

    # Validate input range per RFC 8017: signature integer must be in [0, n).
    sig_int = transform.bytes_to_int(signature)
    if sig_int >= pub_key.n:
        raise VerificationError("Verification failed")

    # "Decrypt" the signature with the public key
    decrypted_int = pow(sig_int, pub_key.e, pub_key.n)
    padded = transform.int_to_bytes(decrypted_int, fill_size=keylength)

    # Verify and strip type 1 padding
    if padded[0:2] != b"\x00\x01":
        raise VerificationError("Verification failed")

    try:
        sep_idx = padded.index(b"\x00", 2)
    except ValueError:
        raise VerificationError("Verification failed") from None

    digest_info = padded[sep_idx + 1 :]

    # Find which hash algorithm's ASN.1 prefix matches
    for hash_name, asn1_prefix in HASH_ASN1.items():
        if digest_info.startswith(asn1_prefix):
            return hash_name

    raise VerificationError("Could not determine hash algorithm from signature")
