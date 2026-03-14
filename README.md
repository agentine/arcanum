# ciphertrust

Pure-Python RSA encryption, signing, and key generation — a drop-in replacement for [python-rsa](https://github.com/sybrenstuvel/python-rsa).

Zero dependencies. Fully typed. Python 3.9+.

## Features

- **RSA key generation** — 512 to 4096+ bit keys with configurable public exponent
- **PKCS#1 v1.5** — encrypt, decrypt, sign, verify (SHA-1 through SHA-512)
- **OAEP (PKCS#1 v2.1)** — encrypt/decrypt with configurable hash and MGF
- **Key serialization** — PKCS#1, PKCS#8, PEM, and DER formats
- **Parallel key generation** — multiprocessing for faster key pair creation
- **python-rsa compatible** — use `import ciphertrust as rsa` as a drop-in replacement

## Installation

```bash
pip install ciphertrust
```

## Quick Start

```python
import ciphertrust

# Generate keys
pub, priv = ciphertrust.newkeys(2048)

# Encrypt / decrypt
ciphertext = ciphertrust.encrypt(b"secret message", pub)
plaintext = ciphertrust.decrypt(ciphertext, priv)

# Sign / verify
signature = ciphertrust.sign(b"important data", priv, "SHA-256")
ciphertrust.verify(b"important data", signature, pub)

# OAEP encryption
ciphertext = ciphertrust.oaep_encrypt(b"secret", pub)
plaintext = ciphertrust.oaep_decrypt(ciphertext, priv)
```

## Key Serialization

```python
# PEM export
pem_pub = pub.save_pkcs1("PEM")
pem_priv = priv.save_pkcs1("PEM")

# PEM import
pub2 = ciphertrust.PublicKey.load_pkcs1(pem_pub)
priv2 = ciphertrust.PrivateKey.load_pkcs1(pem_priv)

# PKCS#8 private key
pkcs8_pem = priv.save_pkcs8("PEM")
priv3 = ciphertrust.PrivateKey.load_pkcs8(pkcs8_pem)
```

## Migrating from python-rsa

ciphertrust is API-compatible with python-rsa. In most cases you can swap the import:

```python
# Before
import rsa
pub, priv = rsa.newkeys(2048)

# After
import ciphertrust as rsa
pub, priv = rsa.newkeys(2048)
```

Or use the compatibility shim:

```python
from ciphertrust import compat as rsa
```

### API Mapping

| python-rsa | ciphertrust | Notes |
|---|---|---|
| `rsa.newkeys(bits)` | `ciphertrust.newkeys(bits)` | Same signature |
| `rsa.encrypt(msg, pub)` | `ciphertrust.encrypt(msg, pub)` | PKCS#1 v1.5 |
| `rsa.decrypt(crypto, priv)` | `ciphertrust.decrypt(crypto, priv)` | Constant-time padding |
| `rsa.sign(msg, priv, hash)` | `ciphertrust.sign(msg, priv, hash)` | Same hash names |
| `rsa.verify(msg, sig, pub)` | `ciphertrust.verify(msg, sig, pub)` | Returns hash method |
| `rsa.PublicKey.load_pkcs1()` | `ciphertrust.PublicKey.load_pkcs1()` | PEM and DER |
| `rsa.PrivateKey.load_pkcs1()` | `ciphertrust.PrivateKey.load_pkcs1()` | PEM and DER |
| — | `ciphertrust.oaep_encrypt()` | New: OAEP support |
| — | `ciphertrust.oaep_decrypt()` | New: OAEP support |
| — | `PrivateKey.load_pkcs8()` | New: PKCS#8 support |

### Key Differences

- **Constant-time operations**: ciphertrust uses constant-time padding validation in `decrypt()` to prevent Bleichenbacher-style timing attacks.
- **RSA blinding**: always enabled for private key operations (not configurable off).
- **OAEP support**: ciphertrust adds PKCS#1 v2.1 OAEP encryption, which python-rsa does not provide.
- **PKCS#8**: ciphertrust can import/export PKCS#8 private keys, enabling interop with OpenSSL `openssl genpkey` output.

## Exceptions

```python
try:
    plaintext = ciphertrust.decrypt(ciphertext, priv)
except ciphertrust.DecryptionError:
    pass  # invalid ciphertext or wrong key

try:
    ciphertrust.verify(message, signature, pub)
except ciphertrust.VerificationError:
    pass  # signature did not match
```

| Exception | Raised when |
|---|---|
| `ciphertrust.CryptoError` | Base class for all ciphertrust errors |
| `ciphertrust.DecryptionError` | Decryption fails (wrong key or corrupt ciphertext) |
| `ciphertrust.VerificationError` | Signature verification fails |

## Security Notes

ciphertrust is a **pure-Python** RSA library intended for education, compatibility, and environments where installing C extensions is impractical.

**When to use ciphertrust:**
- Drop-in replacement for python-rsa with improved security
- Environments where installing compiled packages (like `cryptography`) is not feasible
- Learning and understanding RSA internals

**When to use `cryptography` instead:**
- Production systems handling sensitive data at scale
- When you need constant-time guarantees from hardware-backed operations
- When performance matters (C-backed `cryptography` is ~100x faster for key generation)

**Timing considerations:**
- `decrypt()` uses constant-time padding validation, but the overall Python execution is not guaranteed constant-time by the language runtime.
- RSA blinding is always applied to private-key operations to mitigate timing side channels on modular exponentiation.
- For high-security applications, prefer `cryptography` with hardware-backed constant-time primitives.

## Benchmarks

Compare ciphertrust key generation performance against python-rsa:

```bash
pip install rsa  # optional, enables comparison against python-rsa
python benchmarks/bench_keygen.py 2048 5
```

For parallel key generation:

```python
pub, priv = ciphertrust.newkeys(2048, poolsize=4)
```

## Running Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

Type checking and linting:

```bash
mypy src/ciphertrust/
ruff check src/ciphertrust/
```

## License

MIT
