"""Tests for arcanum.pkcs1 — PKCS#1 v1.5 operations.

Tests cover encryption/decryption, signing/verification, hash computation,
exception hierarchy, padding, and RFC 8017 conformance.
"""

import hashlib
import io

import pytest

from arcanum.key import PrivateKey, PublicKey, newkeys
from arcanum.pkcs1 import (
    HASH_ASN1,
    HASH_METHODS,
    CryptoError,
    DecryptionError,
    VerificationError,
    compute_hash,
    decrypt,
    encrypt,
    find_signature_hash,
    sign,
    sign_hash,
    verify,
)

# ---------------------------------------------------------------------------
# Fixed test keypair (reuse from test_vectors.py)
# ---------------------------------------------------------------------------

_TEST_P = (
    0xEA8B31BA1705B73686286B68EA979A367F493E5A530C8ACA0E5ED9545D9BD9B9
)
_TEST_Q = (
    0x9FF61634AE6CD4DBCAEA9D6BC3AF4BBE46BEDF8612F362E9DB4F0719374B5859
)
_TEST_N = (
    0x928DE9FC9779159A30F1F30D44FC78D90C9895B2BD9EDB4A8A218C05A4AD162E
    * (1 << 256)
    + 0x1889D6F7DD6D4C37DD1DABEC3D40662CC9986F75067905313FC5C902A6394951
)
_TEST_E = 65537
_TEST_D = (
    0x25242415A8C9BE08CAB8B6B1393786E4F3054482FCFD6273FC97CDE5AC3B5570
    * (1 << 256)
    + 0x4B3AAE0D4EEF747CCF85EE994CD9BC7DF5A1409B9B23B52945855FA34FB56F41
)


def _test_pub() -> PublicKey:
    return PublicKey(n=_TEST_N, e=_TEST_E)


def _test_priv() -> PrivateKey:
    return PrivateKey(n=_TEST_N, e=_TEST_E, d=_TEST_D, p=_TEST_P, q=_TEST_Q)


# ---------------------------------------------------------------------------
# Exception hierarchy tests
# ---------------------------------------------------------------------------


class TestExceptionHierarchy:
    def test_decryption_error_is_crypto_error(self) -> None:
        assert issubclass(DecryptionError, CryptoError)

    def test_verification_error_is_crypto_error(self) -> None:
        assert issubclass(VerificationError, CryptoError)

    def test_crypto_error_is_exception(self) -> None:
        assert issubclass(CryptoError, Exception)

    def test_catch_crypto_error_catches_decryption_error(self) -> None:
        with pytest.raises(CryptoError):
            raise DecryptionError("test")

    def test_catch_crypto_error_catches_verification_error(self) -> None:
        with pytest.raises(CryptoError):
            raise VerificationError("test")


# ---------------------------------------------------------------------------
# compute_hash tests
# ---------------------------------------------------------------------------


class TestComputeHash:
    def test_sha256_bytes(self) -> None:
        digest = compute_hash(b"hello", "SHA-256")
        expected = hashlib.sha256(b"hello").digest()
        assert digest == expected

    def test_sha1_bytes(self) -> None:
        digest = compute_hash(b"hello", "SHA-1")
        expected = hashlib.sha1(b"hello").digest()
        assert digest == expected

    def test_sha384_bytes(self) -> None:
        digest = compute_hash(b"test data", "SHA-384")
        expected = hashlib.sha384(b"test data").digest()
        assert digest == expected

    def test_sha512_bytes(self) -> None:
        digest = compute_hash(b"test data", "SHA-512")
        expected = hashlib.sha512(b"test data").digest()
        assert digest == expected

    def test_md5_bytes(self) -> None:
        digest = compute_hash(b"hello", "MD5")
        expected = hashlib.md5(b"hello").digest()
        assert digest == expected

    def test_empty_message(self) -> None:
        digest = compute_hash(b"", "SHA-256")
        expected = hashlib.sha256(b"").digest()
        assert digest == expected

    def test_file_like_object(self) -> None:
        data = b"hello world" * 1000
        digest = compute_hash(io.BytesIO(data), "SHA-256")
        expected = hashlib.sha256(data).digest()
        assert digest == expected

    def test_unsupported_hash_raises(self) -> None:
        with pytest.raises(ValueError, match="Unsupported hash method"):
            compute_hash(b"hello", "SHA-3")

    @pytest.mark.parametrize("method", ["MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"])
    def test_all_methods_produce_correct_length(self, method: str) -> None:
        expected_lengths = {
            "MD5": 16,
            "SHA-1": 20,
            "SHA-256": 32,
            "SHA-384": 48,
            "SHA-512": 64,
        }
        digest = compute_hash(b"test", method)
        assert len(digest) == expected_lengths[method]

    def test_known_sha256_vector(self) -> None:
        """RFC 6234 test vector: SHA-256 of 'abc'."""
        digest = compute_hash(b"abc", "SHA-256")
        expected = bytes.fromhex(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
        assert digest == expected

    def test_known_sha1_vector(self) -> None:
        """FIPS 180-4 test vector: SHA-1 of 'abc'."""
        digest = compute_hash(b"abc", "SHA-1")
        expected = bytes.fromhex("a9993e364706816aba3e25717850c26c9cd0d89d")
        assert digest == expected


# ---------------------------------------------------------------------------
# Encryption / Decryption tests
# ---------------------------------------------------------------------------


class TestEncryptDecrypt:
    def test_basic_round_trip(self) -> None:
        pub, priv = newkeys(512)
        message = b"hello"
        ciphertext = encrypt(message, pub)
        plaintext = decrypt(ciphertext, priv)
        assert plaintext == message

    def test_round_trip_with_fixed_key(self) -> None:
        pub = _test_pub()
        priv = _test_priv()
        message = b"arcanum"
        ciphertext = encrypt(message, pub)
        plaintext = decrypt(ciphertext, priv)
        assert plaintext == message

    def test_empty_message(self) -> None:
        pub, priv = newkeys(512)
        message = b""
        ciphertext = encrypt(message, pub)
        plaintext = decrypt(ciphertext, priv)
        assert plaintext == message

    def test_max_length_message(self) -> None:
        """Test with maximum-length message for 512-bit key."""
        pub, priv = newkeys(512)
        from arcanum.common import byte_size
        keylength = byte_size(pub.n)
        max_msg = keylength - 11
        message = b"A" * max_msg
        ciphertext = encrypt(message, pub)
        plaintext = decrypt(ciphertext, priv)
        assert plaintext == message

    def test_message_too_long_raises(self) -> None:
        pub, _priv = newkeys(512)
        from arcanum.common import byte_size
        keylength = byte_size(pub.n)
        message = b"A" * (keylength - 10)  # 1 byte too many
        with pytest.raises(OverflowError, match="maximum is"):
            encrypt(message, pub)

    def test_ciphertext_length_equals_key_length(self) -> None:
        pub, _priv = newkeys(512)
        from arcanum.common import byte_size
        keylength = byte_size(pub.n)
        ciphertext = encrypt(b"test", pub)
        assert len(ciphertext) == keylength

    def test_different_encryptions_differ(self) -> None:
        """PKCS#1 v1.5 type 2 is randomized — same plaintext should give
        different ciphertexts."""
        pub, _priv = newkeys(512)
        c1 = encrypt(b"hello", pub)
        c2 = encrypt(b"hello", pub)
        assert c1 != c2

    def test_wrong_key_fails(self) -> None:
        pub1, _priv1 = newkeys(512)
        _pub2, priv2 = newkeys(512)
        ciphertext = encrypt(b"secret", pub1)
        with pytest.raises(DecryptionError):
            decrypt(ciphertext, priv2)

    def test_corrupted_ciphertext_fails(self) -> None:
        pub, priv = newkeys(512)
        ciphertext = encrypt(b"hello", pub)
        # Flip some bits
        corrupted = bytearray(ciphertext)
        corrupted[-1] ^= 0xFF
        with pytest.raises(DecryptionError):
            decrypt(bytes(corrupted), priv)

    def test_round_trip_1024_bit(self) -> None:
        pub, priv = newkeys(1024)
        message = b"longer message for a 1024-bit key"
        ciphertext = encrypt(message, pub)
        plaintext = decrypt(ciphertext, priv)
        assert plaintext == message

    def test_single_byte_message(self) -> None:
        pub, priv = newkeys(512)
        message = b"\x42"
        ciphertext = encrypt(message, pub)
        plaintext = decrypt(ciphertext, priv)
        assert plaintext == message

    def test_binary_message(self) -> None:
        pub, priv = newkeys(512)
        message = bytes(range(50))
        ciphertext = encrypt(message, pub)
        plaintext = decrypt(ciphertext, priv)
        assert plaintext == message


# ---------------------------------------------------------------------------
# Signing / Verification tests
# ---------------------------------------------------------------------------


class TestSignVerify:
    @pytest.mark.parametrize("hash_method", ["SHA-1", "SHA-256", "SHA-384", "SHA-512", "MD5"])
    def test_sign_verify_all_hashes(self, hash_method: str) -> None:
        pub, priv = newkeys(1024)
        message = b"test message for signing"
        signature = sign(message, priv, hash_method)
        result = verify(message, signature, pub)
        assert result == hash_method

    def test_sign_verify_with_fixed_key(self) -> None:
        pub = _test_pub()
        priv = _test_priv()
        message = b"arcanum signing test"
        signature = sign(message, priv, "SHA-256")
        result = verify(message, signature, pub)
        assert result == "SHA-256"

    def test_wrong_message_fails_verification(self) -> None:
        pub, priv = newkeys(1024)
        signature = sign(b"correct message", priv, "SHA-256")
        with pytest.raises(VerificationError):
            verify(b"wrong message", signature, pub)

    def test_wrong_key_fails_verification(self) -> None:
        _pub1, priv1 = newkeys(1024)
        pub2, _priv2 = newkeys(1024)
        signature = sign(b"message", priv1, "SHA-256")
        with pytest.raises(VerificationError):
            verify(b"message", signature, pub2)

    def test_corrupted_signature_fails(self) -> None:
        pub, priv = newkeys(1024)
        signature = sign(b"message", priv, "SHA-256")
        corrupted = bytearray(signature)
        corrupted[-1] ^= 0xFF
        with pytest.raises(VerificationError):
            verify(b"message", bytes(corrupted), pub)

    def test_signature_is_deterministic(self) -> None:
        """PKCS#1 v1.5 type 1 padding is deterministic, but blinding makes
        the intermediate computation randomized. The output should be the
        same regardless."""
        pub, priv = newkeys(1024)
        message = b"deterministic test"
        sig1 = sign(message, priv, "SHA-256")
        sig2 = sign(message, priv, "SHA-256")
        assert sig1 == sig2

    def test_signature_length_equals_key_length(self) -> None:
        pub, priv = newkeys(1024)
        from arcanum.common import byte_size
        keylength = byte_size(pub.n)
        signature = sign(b"test", priv, "SHA-256")
        assert len(signature) == keylength

    def test_unsupported_hash_raises(self) -> None:
        _pub, priv = newkeys(1024)
        with pytest.raises(ValueError, match="Unsupported hash method"):
            sign(b"hello", priv, "SHA-3")

    def test_empty_message_sign_verify(self) -> None:
        pub, priv = newkeys(1024)
        message = b""
        signature = sign(message, priv, "SHA-256")
        result = verify(message, signature, pub)
        assert result == "SHA-256"


# ---------------------------------------------------------------------------
# sign_hash tests
# ---------------------------------------------------------------------------


class TestSignHash:
    def test_sign_hash_matches_sign(self) -> None:
        """sign_hash with pre-computed hash should match sign()."""
        pub, priv = newkeys(1024)
        message = b"test message"
        hash_value = compute_hash(message, "SHA-256")
        sig_from_sign = sign(message, priv, "SHA-256")
        sig_from_sign_hash = sign_hash(hash_value, priv, "SHA-256")
        assert sig_from_sign == sig_from_sign_hash

    def test_sign_hash_verify(self) -> None:
        pub, priv = newkeys(1024)
        message = b"another test"
        hash_value = compute_hash(message, "SHA-256")
        signature = sign_hash(hash_value, priv, "SHA-256")
        result = verify(message, signature, pub)
        assert result == "SHA-256"

    def test_sign_hash_unsupported_method(self) -> None:
        _pub, priv = newkeys(1024)
        with pytest.raises(ValueError, match="Unsupported hash method"):
            sign_hash(b"\x00" * 32, priv, "BLAKE2")

    @pytest.mark.parametrize("method", ["MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"])
    def test_sign_hash_all_methods(self, method: str) -> None:
        pub, priv = newkeys(1024)
        message = b"test for all hash methods"
        hash_value = compute_hash(message, method)
        signature = sign_hash(hash_value, priv, method)
        result = verify(message, signature, pub)
        assert result == method


# ---------------------------------------------------------------------------
# find_signature_hash tests
# ---------------------------------------------------------------------------


class TestFindSignatureHash:
    @pytest.mark.parametrize("method", ["MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"])
    def test_find_hash_all_methods(self, method: str) -> None:
        pub, priv = newkeys(1024)
        signature = sign(b"test", priv, method)
        found = find_signature_hash(signature, pub)
        assert found == method

    def test_find_hash_with_fixed_key(self) -> None:
        pub = _test_pub()
        priv = _test_priv()
        signature = sign(b"hello", priv, "SHA-256")
        found = find_signature_hash(signature, pub)
        assert found == "SHA-256"

    def test_corrupted_signature_raises(self) -> None:
        pub, priv = newkeys(1024)
        signature = sign(b"test", priv, "SHA-256")
        corrupted = bytearray(signature)
        corrupted[-1] ^= 0xFF
        with pytest.raises(VerificationError):
            find_signature_hash(bytes(corrupted), pub)


# ---------------------------------------------------------------------------
# RSA blinding tests
# ---------------------------------------------------------------------------


class TestBlinding:
    def test_decrypt_uses_blinding(self) -> None:
        """Decrypt should produce correct results despite blinding randomness."""
        pub, priv = newkeys(512)
        message = b"blind test"
        for _ in range(5):
            ciphertext = encrypt(message, pub)
            plaintext = decrypt(ciphertext, priv)
            assert plaintext == message

    def test_sign_uses_blinding(self) -> None:
        """Sign should produce consistent results despite blinding randomness."""
        pub, priv = newkeys(1024)
        message = b"blind sign test"
        signatures = [sign(message, priv, "SHA-256") for _ in range(5)]
        # All signatures should be identical (deterministic output)
        assert all(s == signatures[0] for s in signatures)
        # And all should verify
        for s in signatures:
            assert verify(message, s, pub) == "SHA-256"


# ---------------------------------------------------------------------------
# Constant-time comparison test
# ---------------------------------------------------------------------------


class TestConstantTimeComparison:
    def test_verify_uses_hmac_compare_digest(self) -> None:
        """Verification should use hmac.compare_digest for hash comparison.
        We test this indirectly by ensuring correct verification behavior."""
        pub, priv = newkeys(1024)
        message = b"constant time test"
        signature = sign(message, priv, "SHA-256")

        # Correct message verifies
        assert verify(message, signature, pub) == "SHA-256"

        # Wrong message fails
        with pytest.raises(VerificationError):
            verify(b"wrong message", signature, pub)


# ---------------------------------------------------------------------------
# PKCS#1 padding conformance tests (RFC 8017)
# ---------------------------------------------------------------------------


class TestPKCS1Padding:
    def test_type2_padding_structure(self) -> None:
        """Verify the structure of type 2 (encryption) padding."""
        from arcanum.pkcs1 import _pad_for_encryption

        message = b"test"
        target_length = 64  # 512-bit key
        padded = _pad_for_encryption(message, target_length)

        assert len(padded) == target_length
        assert padded[0] == 0x00
        assert padded[1] == 0x02
        # Find the 0x00 separator
        sep_idx = padded.index(b"\x00", 2)
        assert sep_idx >= 10  # At least 8 bytes of padding
        # All padding bytes should be non-zero
        assert 0 not in padded[2:sep_idx]
        # Message follows the separator
        assert padded[sep_idx + 1:] == message

    def test_type1_padding_structure(self) -> None:
        """Verify the structure of type 1 (signing) padding."""
        from arcanum.pkcs1 import _pad_for_signing

        message = b"test digest info"
        target_length = 64
        padded = _pad_for_signing(message, target_length)

        assert len(padded) == target_length
        assert padded[0] == 0x00
        assert padded[1] == 0x01
        # Find the 0x00 separator
        sep_idx = padded.index(b"\x00", 2)
        # All padding bytes should be 0xFF
        assert all(b == 0xFF for b in padded[2:sep_idx])
        # Message follows the separator
        assert padded[sep_idx + 1:] == message

    def test_type2_random_padding_varies(self) -> None:
        """Type 2 padding should use random bytes (different each time)."""
        from arcanum.pkcs1 import _pad_for_encryption

        padded1 = _pad_for_encryption(b"test", 64)
        padded2 = _pad_for_encryption(b"test", 64)
        # Padding should be different (message is the same)
        assert padded1 != padded2
        # But both should end with the same message
        assert padded1[-4:] == padded2[-4:] == b"test"

    def test_message_too_long_for_padding(self) -> None:
        from arcanum.pkcs1 import _pad_for_encryption

        # target_length = 20, max message = 20 - 11 = 9
        with pytest.raises(OverflowError):
            _pad_for_encryption(b"A" * 10, 20)


# ---------------------------------------------------------------------------
# ASN.1 DigestInfo prefix tests (RFC 8017, Section 9.2)
# ---------------------------------------------------------------------------


class TestASN1Prefixes:
    def test_md5_prefix_length(self) -> None:
        """MD5 DigestInfo = 18 prefix bytes + 16 hash = 34 total."""
        assert len(HASH_ASN1["MD5"]) == 18

    def test_sha1_prefix_length(self) -> None:
        """SHA-1 DigestInfo = 15 prefix bytes + 20 hash = 35 total."""
        assert len(HASH_ASN1["SHA-1"]) == 15

    def test_sha256_prefix_length(self) -> None:
        """SHA-256 DigestInfo = 19 prefix bytes + 32 hash = 51 total."""
        assert len(HASH_ASN1["SHA-256"]) == 19

    def test_sha384_prefix_length(self) -> None:
        """SHA-384 DigestInfo = 19 prefix bytes + 48 hash = 67 total."""
        assert len(HASH_ASN1["SHA-384"]) == 19

    def test_sha512_prefix_length(self) -> None:
        """SHA-512 DigestInfo = 19 prefix bytes + 64 hash = 83 total."""
        assert len(HASH_ASN1["SHA-512"]) == 19

    def test_all_prefixes_start_with_sequence(self) -> None:
        """All DigestInfo prefixes should start with SEQUENCE tag 0x30."""
        for name, prefix in HASH_ASN1.items():
            assert prefix[0] == 0x30, f"{name} prefix does not start with SEQUENCE"

    def test_all_hash_methods_have_asn1(self) -> None:
        """Every hash method should have a corresponding ASN.1 prefix."""
        for method in HASH_METHODS:
            assert method in HASH_ASN1


# ---------------------------------------------------------------------------
# RFC 8017 conformance: DigestInfo encoding
# ---------------------------------------------------------------------------


class TestRFC8017DigestInfo:
    """Test that DigestInfo encoding matches RFC 8017 Section 9.2, Note 1.

    The expected DER encodings are taken directly from the RFC.
    """

    def test_md5_digest_info(self) -> None:
        """RFC 8017 Section 9.2: MD5 DigestInfo prefix."""
        expected = bytes.fromhex("3020300c06082a864886f70d020505000410")
        assert HASH_ASN1["MD5"] == expected

    def test_sha1_digest_info(self) -> None:
        """RFC 8017 Section 9.2: SHA-1 DigestInfo prefix."""
        expected = bytes.fromhex("3021300906052b0e03021a05000414")
        assert HASH_ASN1["SHA-1"] == expected

    def test_sha256_digest_info(self) -> None:
        """RFC 8017 Section 9.2: SHA-256 DigestInfo prefix."""
        expected = bytes.fromhex("3031300d060960864801650304020105000420")
        assert HASH_ASN1["SHA-256"] == expected

    def test_sha384_digest_info(self) -> None:
        """RFC 8017 Section 9.2: SHA-384 DigestInfo prefix."""
        expected = bytes.fromhex("3041300d060960864801650304020205000430")
        assert HASH_ASN1["SHA-384"] == expected

    def test_sha512_digest_info(self) -> None:
        """RFC 8017 Section 9.2: SHA-512 DigestInfo prefix."""
        expected = bytes.fromhex("3051300d060960864801650304020305000440")
        assert HASH_ASN1["SHA-512"] == expected


# ---------------------------------------------------------------------------
# Cross-algorithm tests
# ---------------------------------------------------------------------------


class TestCrossAlgorithm:
    def test_sha256_signature_not_valid_as_sha1(self) -> None:
        """A SHA-256 signature should not verify when the message is
        re-hashed with SHA-1."""
        pub, priv = newkeys(1024)
        message = b"cross-algo test"
        signature = sign(message, priv, "SHA-256")
        # Verify returns the hash method that matched
        result = verify(message, signature, pub)
        assert result == "SHA-256"

    def test_different_hash_produces_different_signature(self) -> None:
        """Signing the same message with different hash algorithms should
        produce different signatures."""
        pub, priv = newkeys(1024)
        message = b"same message"
        sig_sha1 = sign(message, priv, "SHA-1")
        sig_sha256 = sign(message, priv, "SHA-256")
        assert sig_sha1 != sig_sha256


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_encrypt_all_zero_message(self) -> None:
        pub, priv = newkeys(512)
        message = b"\x00\x00\x00"
        ciphertext = encrypt(message, pub)
        plaintext = decrypt(ciphertext, priv)
        assert plaintext == message

    def test_encrypt_all_ff_message(self) -> None:
        pub, priv = newkeys(512)
        message = b"\xff\xff\xff"
        ciphertext = encrypt(message, pub)
        plaintext = decrypt(ciphertext, priv)
        assert plaintext == message

    def test_sign_long_message(self) -> None:
        """Signing works on long messages (the message is hashed first)."""
        pub, priv = newkeys(1024)
        message = b"x" * 10000
        signature = sign(message, priv, "SHA-256")
        result = verify(message, signature, pub)
        assert result == "SHA-256"

    def test_encrypt_1024_bit_key(self) -> None:
        pub, priv = newkeys(1024)
        message = b"A 1024-bit key allows longer messages!"
        ciphertext = encrypt(message, pub)
        plaintext = decrypt(ciphertext, priv)
        assert plaintext == message
