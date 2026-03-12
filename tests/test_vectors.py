"""Tests with fixed RSA test vectors.

Uses a small, fixed RSA keypair to verify deterministic behavior
of modular exponentiation, key serialization, and PEM round-trips.
"""

from arcanum.core import fast_pow
from arcanum.key import PrivateKey, PublicKey
from arcanum.pem import load_pem, save_pem
from arcanum.transform import bytes_to_int, int_to_bytes

# Fixed 512-bit RSA test keypair (pre-generated with arcanum.key.newkeys)
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
_TEST_PHI = (_TEST_P - 1) * (_TEST_Q - 1)


class TestFixedKeyVector:
    """Tests using a fixed RSA keypair."""

    def test_key_relationship(self) -> None:
        """e * d ≡ 1 (mod phi(n))."""
        assert (_TEST_E * _TEST_D) % _TEST_PHI == 1

    def test_modular_exponentiation(self) -> None:
        """Encrypt and decrypt a known message."""
        message = 42
        ciphertext = fast_pow(message, _TEST_E, _TEST_N)
        plaintext = fast_pow(ciphertext, _TEST_D, _TEST_N)
        assert plaintext == message

    def test_modular_exp_large_message(self) -> None:
        """Test with a larger message."""
        message = 2**128 + 7
        ciphertext = fast_pow(message, _TEST_E, _TEST_N)
        plaintext = fast_pow(ciphertext, _TEST_D, _TEST_N)
        assert plaintext == message

    def test_public_key_from_vector(self) -> None:
        """Construct a PublicKey from test vectors."""
        pub = PublicKey(n=_TEST_N, e=_TEST_E)
        assert pub.n == _TEST_N
        assert pub.e == _TEST_E

    def test_private_key_from_vector(self) -> None:
        """Construct a PrivateKey from test vectors and verify CRT values."""
        priv = PrivateKey(n=_TEST_N, e=_TEST_E, d=_TEST_D, p=_TEST_P, q=_TEST_Q)
        assert priv.dp == _TEST_D % (_TEST_P - 1)
        assert priv.dq == _TEST_D % (_TEST_Q - 1)
        assert (priv.q * priv.q_inv) % priv.p == 1

    def test_blinded_decrypt_with_vector(self) -> None:
        """Test blinded decrypt with fixed key."""
        priv = PrivateKey(n=_TEST_N, e=_TEST_E, d=_TEST_D, p=_TEST_P, q=_TEST_Q)
        message = 42
        encrypted = pow(message, _TEST_E, _TEST_N)
        decrypted = priv.blinded_decrypt(encrypted)
        assert decrypted == message

    def test_blinded_encrypt_with_vector(self) -> None:
        """Test blinded encrypt (signing) with fixed key."""
        pub = PublicKey(n=_TEST_N, e=_TEST_E)
        priv = PrivateKey(n=_TEST_N, e=_TEST_E, d=_TEST_D, p=_TEST_P, q=_TEST_Q)
        message = 12345
        signed = priv.blinded_encrypt(message)
        recovered = pow(signed, pub.e, pub.n)
        assert recovered == message


class TestFixedKeyPEMRoundTrip:
    """PEM/DER round-trips with fixed test vectors."""

    def test_public_key_pem_round_trip(self) -> None:
        pub = PublicKey(n=_TEST_N, e=_TEST_E)
        pem_data = pub.save_pkcs1("PEM")
        loaded = PublicKey.load_pkcs1(pem_data)
        assert loaded.n == _TEST_N
        assert loaded.e == _TEST_E
        assert loaded == pub

    def test_public_key_der_round_trip(self) -> None:
        pub = PublicKey(n=_TEST_N, e=_TEST_E)
        der_data = pub.save_pkcs1("DER")
        loaded = PublicKey.load_pkcs1(der_data, "DER")
        assert loaded == pub

    def test_private_key_pem_round_trip(self) -> None:
        priv = PrivateKey(n=_TEST_N, e=_TEST_E, d=_TEST_D, p=_TEST_P, q=_TEST_Q)
        pem_data = priv.save_pkcs1("PEM")
        loaded = PrivateKey.load_pkcs1(pem_data)
        assert loaded.n == _TEST_N
        assert loaded.e == _TEST_E
        assert loaded.d == _TEST_D
        assert loaded.p == _TEST_P
        assert loaded.q == _TEST_Q
        assert loaded == priv

    def test_private_key_der_round_trip(self) -> None:
        priv = PrivateKey(n=_TEST_N, e=_TEST_E, d=_TEST_D, p=_TEST_P, q=_TEST_Q)
        der_data = priv.save_pkcs1("DER")
        loaded = PrivateKey.load_pkcs1(der_data, "DER")
        assert loaded == priv


class TestPEMFormat:
    """Test PEM encoding/decoding itself."""

    def test_save_load_round_trip(self) -> None:
        data = b"\x01\x02\x03\x04\x05"
        marker = "TEST DATA"
        pem_bytes = save_pem(data, marker)
        loaded_marker, loaded_data = load_pem(pem_bytes)
        assert loaded_marker == marker
        assert loaded_data == data

    def test_pem_line_length(self) -> None:
        """PEM lines should be at most 64 characters."""
        data = bytes(range(256)) * 4  # Large enough for multi-line
        pem_bytes = save_pem(data, "TEST")
        lines = pem_bytes.decode("ascii").strip().split("\n")
        for line in lines[1:-1]:  # Skip header and footer
            assert len(line) <= 64

    def test_large_data_round_trip(self) -> None:
        """Round-trip with data larger than one base64 line."""
        data = bytes(range(256)) * 10
        pem_bytes = save_pem(data, "LARGE TEST")
        loaded_marker, loaded_data = load_pem(pem_bytes)
        assert loaded_marker == "LARGE TEST"
        assert loaded_data == data


class TestTransformVectors:
    """Fixed test vectors for byte/int transforms."""

    def test_known_bytes_to_int(self) -> None:
        assert bytes_to_int(b"\x00") == 0
        assert bytes_to_int(b"\x01") == 1
        assert bytes_to_int(b"\x80") == 128
        assert bytes_to_int(b"\xff") == 255
        assert bytes_to_int(b"\x01\x00") == 256
        assert bytes_to_int(b"\xff\xff") == 65535

    def test_known_int_to_bytes(self) -> None:
        assert int_to_bytes(0) == b"\x00"
        assert int_to_bytes(1) == b"\x01"
        assert int_to_bytes(128) == b"\x80"
        assert int_to_bytes(255) == b"\xff"
        assert int_to_bytes(256) == b"\x01\x00"
        assert int_to_bytes(65535) == b"\xff\xff"


class TestModularExponentiation:
    """Test core.fast_pow with known vectors."""

    def test_small_values(self) -> None:
        assert fast_pow(2, 10, 1000) == 24  # 1024 % 1000
        assert fast_pow(3, 4, 5) == 1  # 81 % 5
        assert fast_pow(7, 3, 13) == 5  # 343 % 13

    def test_identity(self) -> None:
        assert fast_pow(42, 1, 100) == 42
        assert fast_pow(42, 0, 100) == 1

    def test_rsa_like(self) -> None:
        """Small RSA-like computation."""
        # p=61, q=53, n=3233, e=17, d=2753
        n, e, d = 3233, 17, 2753
        message = 65
        cipher = fast_pow(message, e, n)
        assert cipher == 2790
        plain = fast_pow(cipher, d, n)
        assert plain == message
