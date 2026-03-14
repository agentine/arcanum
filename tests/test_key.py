"""Tests for ciphertrust.key — key generation and serialization."""

import pytest

from ciphertrust.key import PrivateKey, PublicKey, newkeys


class TestNewkeys:
    def test_512_bit(self) -> None:
        pub, priv = newkeys(512)
        assert pub.n.bit_length() >= 512
        assert pub.e == 65537
        assert priv.n == pub.n
        assert priv.e == pub.e

    def test_custom_exponent(self) -> None:
        pub, priv = newkeys(512, exponent=3)
        assert pub.e == 3
        assert priv.e == 3

    def test_too_small_raises(self) -> None:
        with pytest.raises(ValueError, match="at least 16"):
            newkeys(8)

    def test_encrypt_decrypt_round_trip(self) -> None:
        """Basic RSA: m^e mod n -> c, c^d mod n -> m."""
        pub, priv = newkeys(512)
        message = 42
        encrypted = pow(message, pub.e, pub.n)
        decrypted = priv.blinded_decrypt(encrypted)
        assert decrypted == message

    def test_sign_verify_round_trip(self) -> None:
        """Signing: m^d mod n -> s, s^e mod n -> m."""
        pub, priv = newkeys(512)
        message = 12345
        signature = priv.blinded_encrypt(message)
        recovered = pow(signature, pub.e, pub.n)
        assert recovered == message

    def test_accurate_mode(self) -> None:
        pub, _priv = newkeys(512, accurate=True)
        assert pub.n.bit_length() == 512


class TestPublicKeyPEM:
    def test_pem_round_trip(self) -> None:
        pub, _priv = newkeys(512)
        pem_data = pub.save_pkcs1("PEM")
        loaded = PublicKey.load_pkcs1(pem_data, "PEM")
        assert loaded == pub

    def test_der_round_trip(self) -> None:
        pub, _priv = newkeys(512)
        der_data = pub.save_pkcs1("DER")
        loaded = PublicKey.load_pkcs1(der_data, "DER")
        assert loaded == pub

    def test_pem_format(self) -> None:
        pub, _priv = newkeys(512)
        pem_data = pub.save_pkcs1("PEM")
        assert pem_data.startswith(b"-----BEGIN RSA PUBLIC KEY-----")
        assert pem_data.strip().endswith(b"-----END RSA PUBLIC KEY-----")

    def test_wrong_marker_raises(self) -> None:
        _pub, priv = newkeys(512)
        priv_pem = priv.save_pkcs1("PEM")
        with pytest.raises(ValueError, match="RSA PUBLIC KEY"):
            PublicKey.load_pkcs1(priv_pem)


class TestPrivateKeyPEM:
    def test_pem_round_trip(self) -> None:
        _pub, priv = newkeys(512)
        pem_data = priv.save_pkcs1("PEM")
        loaded = PrivateKey.load_pkcs1(pem_data, "PEM")
        assert loaded == priv

    def test_der_round_trip(self) -> None:
        _pub, priv = newkeys(512)
        der_data = priv.save_pkcs1("DER")
        loaded = PrivateKey.load_pkcs1(der_data, "DER")
        assert loaded == priv

    def test_pem_format(self) -> None:
        _pub, priv = newkeys(512)
        pem_data = priv.save_pkcs1("PEM")
        assert pem_data.startswith(b"-----BEGIN RSA PRIVATE KEY-----")
        assert pem_data.strip().endswith(b"-----END RSA PRIVATE KEY-----")

    def test_crt_precomputed(self) -> None:
        _pub, priv = newkeys(512)
        assert priv.dp == priv.d % (priv.p - 1)
        assert priv.dq == priv.d % (priv.q - 1)
        assert (priv.q * priv.q_inv) % priv.p == 1

    def test_wrong_marker_raises(self) -> None:
        pub, _priv = newkeys(512)
        pub_pem = pub.save_pkcs1("PEM")
        with pytest.raises(ValueError, match="RSA PRIVATE KEY"):
            PrivateKey.load_pkcs1(pub_pem)


class TestBlindedOps:
    def test_blinded_decrypt_correctness(self) -> None:
        """Blinded decrypt should produce same result as raw pow()."""
        pub, priv = newkeys(512)
        message = 99
        encrypted = pow(message, pub.e, pub.n)
        decrypted = priv.blinded_decrypt(encrypted)
        assert decrypted == message

    def test_blinded_encrypt_correctness(self) -> None:
        """Blinded encrypt (sign) should produce verifiable signatures."""
        pub, priv = newkeys(512)
        message = 77
        signed = priv.blinded_encrypt(message)
        recovered = pow(signed, pub.e, pub.n)
        assert recovered == message

    def test_blinded_ops_multiple(self) -> None:
        """Run blinded ops multiple times to exercise randomized blinding."""
        pub, priv = newkeys(512)
        for msg in [1, 2, 100, 1000, pub.n - 1]:
            encrypted = pow(msg, pub.e, pub.n)
            assert priv.blinded_decrypt(encrypted) == msg


class TestOpenSSL:
    def test_openssl_der_round_trip(self) -> None:
        """Test loading an OpenSSL SubjectPublicKeyInfo DER key."""
        pub, _priv = newkeys(512)

        # Build a SubjectPublicKeyInfo wrapper manually
        rsa_pubkey_der = pub.save_pkcs1("DER")

        # BIT STRING: 0x03 + length + 0x00 (unused bits) + rsa_pubkey_der
        bit_string_payload = b"\x00" + rsa_pubkey_der
        if len(bit_string_payload) < 0x80:
            bit_string = bytes([0x03, len(bit_string_payload)]) + bit_string_payload
        else:
            ln_bytes = len(bit_string_payload).to_bytes(
                (len(bit_string_payload).bit_length() + 7) // 8, "big"
            )
            bit_string = (
                bytes([0x03, 0x80 | len(ln_bytes)]) + ln_bytes + bit_string_payload
            )

        # AlgorithmIdentifier SEQUENCE: rsaEncryption OID + NULL
        oid = bytes([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])
        null = bytes([0x05, 0x00])
        alg_id_content = oid + null
        alg_id = bytes([0x30, len(alg_id_content)]) + alg_id_content

        # Outer SEQUENCE
        outer_content = alg_id + bit_string
        if len(outer_content) < 0x80:
            spki = bytes([0x30, len(outer_content)]) + outer_content
        else:
            ln_bytes = len(outer_content).to_bytes(
                (len(outer_content).bit_length() + 7) // 8, "big"
            )
            spki = bytes([0x30, 0x80 | len(ln_bytes)]) + ln_bytes + outer_content

        loaded = PublicKey.load_pkcs1_openssl_der(spki)
        assert loaded == pub

    def test_openssl_pem_round_trip(self) -> None:
        """Test loading an OpenSSL SubjectPublicKeyInfo PEM key."""
        from ciphertrust import pem as pem_mod

        pub, _priv = newkeys(512)

        # Build SPKI DER (same as above)
        rsa_pubkey_der = pub.save_pkcs1("DER")
        bit_string_payload = b"\x00" + rsa_pubkey_der
        if len(bit_string_payload) < 0x80:
            bit_string = bytes([0x03, len(bit_string_payload)]) + bit_string_payload
        else:
            ln_bytes = len(bit_string_payload).to_bytes(
                (len(bit_string_payload).bit_length() + 7) // 8, "big"
            )
            bit_string = (
                bytes([0x03, 0x80 | len(ln_bytes)]) + ln_bytes + bit_string_payload
            )

        oid = bytes([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])
        null = bytes([0x05, 0x00])
        alg_id_content = oid + null
        alg_id = bytes([0x30, len(alg_id_content)]) + alg_id_content

        outer_content = alg_id + bit_string
        if len(outer_content) < 0x80:
            spki = bytes([0x30, len(outer_content)]) + outer_content
        else:
            ln_bytes = len(outer_content).to_bytes(
                (len(outer_content).bit_length() + 7) // 8, "big"
            )
            spki = bytes([0x30, 0x80 | len(ln_bytes)]) + ln_bytes + outer_content

        pem_data = pem_mod.save_pem(spki, "PUBLIC KEY")
        loaded = PublicKey.load_pkcs1_openssl_pem(pem_data)
        assert loaded == pub
