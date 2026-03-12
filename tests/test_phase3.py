"""Tests for Phase 3 features: OAEP, parallel keygen, compat shim, PKCS#8, __init__."""

import importlib
import multiprocessing

import pytest

from arcanum import key, pkcs1, common, transform, pem
from arcanum.key import PublicKey, PrivateKey, newkeys


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def keypair_512():
    """A 512-bit key pair (small for fast tests)."""
    return newkeys(512)


@pytest.fixture(scope="module")
def keypair_1024():
    """A 1024-bit key pair for OAEP tests (needs larger key for SHA-256)."""
    return newkeys(1024)


# ---------------------------------------------------------------------------
# OAEP (pkcs1_v2) tests
# ---------------------------------------------------------------------------

class TestOAEP:
    def test_encrypt_decrypt_roundtrip(self, keypair_1024):
        from arcanum.pkcs1_v2 import encrypt, decrypt
        pub, priv = keypair_1024
        message = b"hello OAEP"
        ciphertext = encrypt(message, pub)
        plaintext = decrypt(ciphertext, priv)
        assert plaintext == message

    def test_encrypt_decrypt_empty_message(self, keypair_1024):
        from arcanum.pkcs1_v2 import encrypt, decrypt
        pub, priv = keypair_1024
        ciphertext = encrypt(b"", pub)
        plaintext = decrypt(ciphertext, priv)
        assert plaintext == b""

    def test_encrypt_decrypt_max_length(self, keypair_1024):
        from arcanum.pkcs1_v2 import encrypt, decrypt
        pub, priv = keypair_1024
        k = common.byte_size(pub.n)
        h_len = 32  # SHA-256
        max_len = k - 2 * h_len - 2
        message = b"x" * max_len
        ciphertext = encrypt(message, pub)
        plaintext = decrypt(ciphertext, priv)
        assert plaintext == message

    def test_encrypt_message_too_long(self, keypair_1024):
        from arcanum.pkcs1_v2 import encrypt
        pub, _ = keypair_1024
        k = common.byte_size(pub.n)
        h_len = 32
        max_len = k - 2 * h_len - 2
        with pytest.raises(ValueError, match="Message too long"):
            encrypt(b"x" * (max_len + 1), pub)

    def test_decrypt_wrong_key(self, keypair_1024):
        from arcanum.pkcs1_v2 import encrypt, decrypt
        from arcanum.pkcs1 import DecryptionError
        pub, _ = keypair_1024
        _, other_priv = newkeys(1024)
        ciphertext = encrypt(b"secret", pub)
        with pytest.raises(DecryptionError):
            decrypt(ciphertext, other_priv)

    def test_decrypt_corrupted_ciphertext(self, keypair_1024):
        from arcanum.pkcs1_v2 import encrypt, decrypt
        from arcanum.pkcs1 import DecryptionError
        pub, priv = keypair_1024
        ciphertext = encrypt(b"test", pub)
        corrupted = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]
        with pytest.raises(DecryptionError):
            decrypt(corrupted, priv)

    def test_decrypt_wrong_length(self, keypair_1024):
        from arcanum.pkcs1_v2 import decrypt
        from arcanum.pkcs1 import DecryptionError
        _, priv = keypair_1024
        with pytest.raises(DecryptionError):
            decrypt(b"short", priv)

    def test_encrypt_with_label(self, keypair_1024):
        from arcanum.pkcs1_v2 import encrypt, decrypt
        pub, priv = keypair_1024
        message = b"labeled data"
        label = b"my-label"
        ciphertext = encrypt(message, pub, label=label)
        plaintext = decrypt(ciphertext, priv, label=label)
        assert plaintext == message

    def test_decrypt_wrong_label(self, keypair_1024):
        from arcanum.pkcs1_v2 import encrypt, decrypt
        from arcanum.pkcs1 import DecryptionError
        pub, priv = keypair_1024
        ciphertext = encrypt(b"data", pub, label=b"correct")
        with pytest.raises(DecryptionError):
            decrypt(ciphertext, priv, label=b"wrong")

    def test_ciphertext_is_different_each_time(self, keypair_1024):
        from arcanum.pkcs1_v2 import encrypt
        pub, _ = keypair_1024
        c1 = encrypt(b"same", pub)
        c2 = encrypt(b"same", pub)
        assert c1 != c2  # Random seed makes each encryption unique


class TestMGF1:
    def test_mgf1_output_length(self):
        from arcanum.pkcs1_v2 import _mgf1
        seed = b"test seed"
        mask = _mgf1(seed, 50)
        assert len(mask) == 50

    def test_mgf1_deterministic(self):
        from arcanum.pkcs1_v2 import _mgf1
        seed = b"deterministic"
        assert _mgf1(seed, 32) == _mgf1(seed, 32)

    def test_mgf1_different_seeds(self):
        from arcanum.pkcs1_v2 import _mgf1
        assert _mgf1(b"seed1", 32) != _mgf1(b"seed2", 32)


# ---------------------------------------------------------------------------
# Parallel keygen tests
# ---------------------------------------------------------------------------

class TestParallelKeygen:
    def test_parallel_newkeys_produces_valid_keys(self):
        """Parallel keygen should produce keys that encrypt/decrypt correctly."""
        pub, priv = newkeys(512, poolsize=2)
        assert isinstance(pub, PublicKey)
        assert isinstance(priv, PrivateKey)
        assert pub.n == priv.n
        assert pub.e == priv.e

        # Verify encrypt/decrypt works
        msg = b"parallel test"
        ct = pkcs1.encrypt(msg, pub)
        pt = pkcs1.decrypt(ct, priv)
        assert pt == msg

    def test_parallel_newkeys_accurate(self):
        """Accurate mode with poolsize > 1 should produce exact bit count."""
        pub, priv = newkeys(512, accurate=True, poolsize=2)
        assert common.bit_size(pub.n) == 512

    def test_parallel_module_find_p_q(self):
        """Direct test of _find_p_q_parallel."""
        from arcanum.parallel import _find_p_q_parallel
        p, q = _find_p_q_parallel(256, poolsize=2)
        assert p > q
        assert p != q
        n = p * q
        assert common.bit_size(n) >= 256

    def test_poolsize_1_uses_serial(self):
        """poolsize=1 should NOT use multiprocessing."""
        pub, priv = newkeys(256, poolsize=1)
        assert isinstance(pub, PublicKey)
        assert isinstance(priv, PrivateKey)


# ---------------------------------------------------------------------------
# PKCS#8 tests
# ---------------------------------------------------------------------------

class TestPKCS8:
    def test_save_load_pkcs8_der_roundtrip(self, keypair_512):
        _, priv = keypair_512
        der = priv.save_pkcs8(format="DER")
        loaded = PrivateKey.load_pkcs8(der, format="DER")
        assert loaded == priv

    def test_save_load_pkcs8_pem_roundtrip(self, keypair_512):
        _, priv = keypair_512
        pem_data = priv.save_pkcs8(format="PEM")
        assert b"-----BEGIN PRIVATE KEY-----" in pem_data
        assert b"-----END PRIVATE KEY-----" in pem_data
        loaded = PrivateKey.load_pkcs8(pem_data, format="PEM")
        assert loaded == priv

    def test_pkcs8_pem_wrong_marker(self):
        _, priv = newkeys(256)
        # Save as PKCS#1 (RSA PRIVATE KEY) and try loading as PKCS#8
        pkcs1_pem = priv.save_pkcs1(format="PEM")
        with pytest.raises(ValueError, match="Expected 'PRIVATE KEY'"):
            PrivateKey.load_pkcs8(pkcs1_pem, format="PEM")

    def test_pkcs8_der_structure(self, keypair_512):
        """Verify the PKCS#8 DER starts with the expected structure."""
        _, priv = keypair_512
        der = priv.save_pkcs8(format="DER")
        # Must start with SEQUENCE tag
        assert der[0] == 0x30
        # Should be larger than PKCS#1 DER (has the wrapper)
        pkcs1_der = priv.save_pkcs1(format="DER")
        assert len(der) > len(pkcs1_der)

    def test_pkcs8_preserves_crt_values(self, keypair_512):
        """Loading from PKCS#8 should recompute CRT values correctly."""
        _, priv = keypair_512
        pem_data = priv.save_pkcs8(format="PEM")
        loaded = PrivateKey.load_pkcs8(pem_data)
        assert loaded.dp == priv.dp
        assert loaded.dq == priv.dq
        assert loaded.q_inv == priv.q_inv

    def test_pkcs8_key_works_for_signing(self, keypair_512):
        """A key loaded from PKCS#8 should work for sign/verify."""
        pub, priv = keypair_512
        pem_data = priv.save_pkcs8(format="PEM")
        loaded = PrivateKey.load_pkcs8(pem_data)
        sig = pkcs1.sign(b"test message", loaded, "SHA-256")
        assert pkcs1.verify(b"test message", sig, pub) == "SHA-256"


# ---------------------------------------------------------------------------
# Compat shim tests
# ---------------------------------------------------------------------------

class TestCompat:
    def test_import_as_rsa(self):
        """import arcanum.compat should provide python-rsa-like API."""
        from arcanum import compat
        assert hasattr(compat, "newkeys")
        assert hasattr(compat, "encrypt")
        assert hasattr(compat, "decrypt")
        assert hasattr(compat, "sign")
        assert hasattr(compat, "verify")
        assert hasattr(compat, "PublicKey")
        assert hasattr(compat, "PrivateKey")

    def test_compat_newkeys_encrypt_decrypt(self):
        from arcanum import compat
        pub, priv = compat.newkeys(512)
        ct = compat.encrypt(b"compat test", pub)
        pt = compat.decrypt(ct, priv)
        assert pt == b"compat test"

    def test_compat_sign_verify(self):
        from arcanum import compat
        pub, priv = compat.newkeys(512)
        sig = compat.sign(b"message", priv, "SHA-256")
        assert compat.verify(b"message", sig, pub) == "SHA-256"

    def test_compat_oaep(self):
        from arcanum import compat
        pub, priv = compat.newkeys(1024)
        ct = compat.oaep_encrypt(b"oaep compat", pub)
        pt = compat.oaep_decrypt(ct, priv)
        assert pt == b"oaep compat"

    def test_compat_utilities(self):
        from arcanum import compat
        assert compat.bit_size(255) == 8
        assert compat.byte_size(256) == 2
        assert compat.bytes_to_int(b"\x01\x00") == 256
        assert compat.int_to_bytes(256) == b"\x01\x00"

    def test_compat_exceptions(self):
        from arcanum import compat
        assert issubclass(compat.DecryptionError, compat.CryptoError)
        assert issubclass(compat.VerificationError, compat.CryptoError)

    def test_compat_all_exports(self):
        from arcanum import compat
        for name in compat.__all__:
            assert hasattr(compat, name), f"Missing export: {name}"

    def test_compat_pem_functions(self):
        from arcanum import compat
        der = b"\x30\x03\x02\x01\x42"  # A tiny DER SEQUENCE
        pem_data = compat.save_pem(der, "TEST")
        assert b"-----BEGIN TEST-----" in pem_data
        marker, loaded = compat.load_pem(pem_data)
        assert marker == "TEST"
        assert loaded == der


# ---------------------------------------------------------------------------
# __init__.py public API tests
# ---------------------------------------------------------------------------

class TestPublicAPI:
    def test_version(self):
        import arcanum
        assert hasattr(arcanum, "__version__")
        assert arcanum.__version__ == "0.1.0"

    def test_all_exports_exist(self):
        import arcanum
        for name in arcanum.__all__:
            assert hasattr(arcanum, name), f"Missing export: {name}"

    def test_top_level_encrypt_decrypt(self):
        import arcanum
        pub, priv = arcanum.newkeys(512)
        ct = arcanum.encrypt(b"top-level", pub)
        pt = arcanum.decrypt(ct, priv)
        assert pt == b"top-level"

    def test_top_level_sign_verify(self):
        import arcanum
        pub, priv = arcanum.newkeys(512)
        sig = arcanum.sign(b"sign me", priv, "SHA-256")
        assert arcanum.verify(b"sign me", sig, pub) == "SHA-256"

    def test_top_level_oaep(self):
        import arcanum
        pub, priv = arcanum.newkeys(1024)
        ct = arcanum.oaep_encrypt(b"oaep top", pub)
        pt = arcanum.oaep_decrypt(ct, priv)
        assert pt == b"oaep top"

    def test_top_level_exceptions(self):
        import arcanum
        assert issubclass(arcanum.DecryptionError, arcanum.CryptoError)
        assert issubclass(arcanum.VerificationError, arcanum.CryptoError)

    def test_top_level_utilities(self):
        import arcanum
        assert arcanum.bit_size(1023) == 10
        assert arcanum.byte_size(1023) == 2
        assert arcanum.bytes_to_int(b"\xff") == 255
        assert arcanum.int_to_bytes(255) == b"\xff"
