# Arcanum — Pure-Python RSA Cryptography

## Overview

**Arcanum** is a modern, pure-Python RSA implementation that replaces the archived [python-rsa](https://github.com/sybrenstuvel/python-rsa) package (~377M monthly PyPI downloads). Python-rsa was archived by its sole maintainer on April 20, 2025, leaving the Python ecosystem without an actively maintained pure-Python RSA library.

**Package name:** `arcanum` (verified available on PyPI)

## Target

| Attribute | Value |
|---|---|
| Replaces | `rsa` (python-rsa) |
| PyPI downloads | ~377M/month |
| Maintainer status | Archived, sole maintainer abandoned |
| Dependent packages | 1,320+ on PyPI |
| Key dependent | `google-auth` (330M+/month) |
| Last release | v4.9.1 (April 16, 2025 — final) |

## Why Pure-Python Matters

The `cryptography` package provides RSA via OpenSSL/C bindings but requires a **Rust toolchain + OpenSSL development headers** to build from source. Pure-Python RSA is essential for:

- **Minimal containers** (Alpine Linux, distroless) without C/Rust toolchains
- **Serverless functions** with restricted build environments
- **MicroPython / CircuitPython** embedded devices
- **CI environments** without system-level dependencies
- **Air-gapped systems** where installing native build tools is restricted
- **Educational use** where readable source code matters

## Design Principles

1. **API-compatible with python-rsa** — drop-in replacement via import alias
2. **Zero dependencies** — pure Python, no C extensions, no external packages
3. **Python 3.9+** — drop Python 3.6-3.8 (EOL), use modern typing and stdlib features
4. **Security-first** — constant-time comparisons, blinding, secure random, clear security docs
5. **Fully typed** — py.typed marker, strict mypy, complete type annotations
6. **Modern packaging** — src/ layout, pyproject.toml only, no setup.py/setup.cfg

## API Surface (python-rsa compatible)

### Core Functions

```python
arcanum.newkeys(nbits: int, accurate: bool = False, poolsize: int = 1, exponent: int = 65537) -> tuple[PublicKey, PrivateKey]
arcanum.encrypt(message: bytes, pub_key: PublicKey) -> bytes          # PKCS#1 v1.5
arcanum.decrypt(crypto: bytes, priv_key: PrivateKey) -> bytes         # PKCS#1 v1.5
arcanum.sign(message: bytes, priv_key: PrivateKey, hash_method: str) -> bytes
arcanum.verify(message: bytes, signature: bytes, pub_key: PublicKey) -> str
arcanum.compute_hash(message: bytes | typing.BinaryIO, method_name: str) -> bytes
arcanum.sign_hash(hash_value: bytes, priv_key: PrivateKey, hash_method: str) -> bytes
arcanum.find_signature_hash(signature: bytes, pub_key: PublicKey) -> str
```

### Key Classes

```python
class arcanum.PublicKey(n: int, e: int):
    def save_pkcs1(self, format: str = "PEM") -> bytes
    @classmethod
    def load_pkcs1(cls, keyfile: bytes, format: str = "PEM") -> PublicKey
    @classmethod
    def load_pkcs1_openssl_pem(cls, keyfile: bytes) -> PublicKey
    @classmethod
    def load_pkcs1_openssl_der(cls, keyfile: bytes) -> PublicKey

class arcanum.PrivateKey(n: int, e: int, d: int, p: int, q: int):
    def save_pkcs1(self, format: str = "PEM") -> bytes
    @classmethod
    def load_pkcs1(cls, keyfile: bytes, format: str = "PEM") -> PrivateKey
    def blinded_decrypt(self, encrypted: int) -> int
    def blinded_encrypt(self, message: int) -> int
```

### Exceptions

```python
arcanum.pkcs1.CryptoError          # Base exception
arcanum.pkcs1.DecryptionError      # Decryption failed
arcanum.pkcs1.VerificationError    # Signature verification failed
```

### Internal Modules

| Module | Purpose |
|---|---|
| `arcanum.key` | PublicKey and PrivateKey classes |
| `arcanum.pkcs1` | PKCS#1 v1.5 encryption, signing, padding |
| `arcanum.pem` | PEM encoding/decoding |
| `arcanum.core` | Low-level modular exponentiation |
| `arcanum.prime` | Miller-Rabin primality testing, prime generation |
| `arcanum.randnum` | Cryptographically secure random number generation |
| `arcanum.transform` | Byte ↔ integer transformations |
| `arcanum.common` | Shared utilities (byte_size, bit_size) |
| `arcanum.parallel` | Parallel key generation using multiprocessing |

### Compatibility Layer

```python
# Drop-in migration: change one import
# Before: import rsa
# After:  import arcanum as rsa
```

The `arcanum.compat` module will provide `rsa`-named exports for projects that cannot change import paths via sys.modules patching.

## Improvements Over python-rsa

1. **Constant-time signature verification** — use `hmac.compare_digest()` for hash comparisons
2. **Improved blinding** — always-on RSA blinding for private key operations to mitigate timing attacks
3. **Modern hash defaults** — SHA-256 as recommended default (python-rsa examples used SHA-1)
4. **PKCS#1 v2.1 OAEP** — add OAEP padding support (python-rsa had a stub `pkcs1_v2` module)
5. **PKCS#8 key support** — import/export PKCS#8 private keys (common in modern tooling)
6. **Deterministic tests** — reproducible test vectors from NIST/PKCS#1 spec
7. **No deprecated algorithms** — drop MD5 signing support, keep verification for legacy compat
8. **Security documentation** — clear docs on timing attack limitations and when to use `cryptography` instead

## Architecture

```
src/arcanum/
├── __init__.py          # Public API re-exports
├── py.typed             # PEP 561 marker
├── key.py               # PublicKey, PrivateKey classes
├── pkcs1.py             # PKCS#1 v1.5 operations (encrypt, decrypt, sign, verify)
├── pkcs1_v2.py          # PKCS#1 v2.1 OAEP operations
├── pem.py               # PEM encoding/decoding
├── core.py              # Modular exponentiation
├── prime.py             # Prime generation, Miller-Rabin
├── randnum.py           # Secure random number generation
├── transform.py         # bytes_to_int, int_to_bytes
├── common.py            # byte_size, bit_size utilities
├── parallel.py          # Multiprocessing key generation
└── compat.py            # python-rsa compatibility shim
tests/
├── test_key.py
├── test_pkcs1.py
├── test_pkcs1_v2.py
├── test_pem.py
├── test_prime.py
├── test_transform.py
├── test_compat.py
└── test_vectors.py      # NIST/RFC test vectors
```

## Implementation Phases

### Phase 1: Core Math & Key Operations
- `transform.py` — bytes ↔ int conversions
- `common.py` — byte_size, bit_size utilities
- `randnum.py` — secure random number generation using `secrets` module
- `prime.py` — Miller-Rabin primality test, prime generation
- `core.py` — modular exponentiation (`pow(base, exp, mod)`)
- `key.py` — PublicKey, PrivateKey classes with PKCS#1 PEM/DER serialization
- `pem.py` — PEM encoding/decoding
- `newkeys()` function — RSA key pair generation
- Tests for all of the above with known test vectors

### Phase 2: PKCS#1 v1.5 Operations
- `pkcs1.py` — PKCS#1 v1.5 padding, encryption, decryption
- Signing and verification with all supported hash algorithms
- `compute_hash()`, `sign_hash()`, `find_signature_hash()`
- RSA blinding for all private key operations
- Constant-time hash comparison in verification
- Exception hierarchy (CryptoError, DecryptionError, VerificationError)
- Tests with RFC 8017 test vectors

### Phase 3: Advanced Features
- `pkcs1_v2.py` — OAEP encryption/decryption (PKCS#1 v2.1)
- PKCS#8 private key import/export
- OpenSSL PEM/DER public key import
- `parallel.py` — multiprocessing key generation
- `compat.py` — python-rsa compatibility layer
- `__init__.py` — clean public API with `__all__`
- Large file signing/verification (streaming hash)

### Phase 4: Polish & Ship
- Comprehensive README with migration guide from python-rsa
- Security documentation (timing attack caveats, when to use `cryptography`)
- Benchmarks vs python-rsa
- CI pipeline (GitHub Actions: lint, type check, test on 3.9-3.13 + PyPy)
- pyproject.toml configuration (flit or hatchling)
- PyPI publish as `arcanum`
- Compatibility test suite: generate keys/signatures with python-rsa, verify with arcanum and vice versa

## Package Metadata

```toml
[project]
name = "arcanum"
description = "Pure-Python RSA encryption, signing, and key generation — drop-in python-rsa replacement"
requires-python = ">=3.9"
license = "MIT"
keywords = ["rsa", "crypto", "encryption", "signing", "pkcs1", "pure-python"]
classifiers = [
    "Development Status :: 4 - Beta",
    "Topic :: Security :: Cryptography",
    "Typing :: Typed",
]
```

## Success Criteria

- [ ] All python-rsa public API functions implemented and tested
- [ ] Cross-compatibility: keys/signatures generated by python-rsa work with arcanum
- [ ] Zero dependencies, pure Python
- [ ] Full type annotations, passes strict mypy
- [ ] NIST/RFC test vectors pass
- [ ] CI green on Python 3.9–3.13 + PyPy
- [ ] Published on PyPI as `arcanum`
- [ ] Migration guide in README
