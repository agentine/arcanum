# Changelog

All notable changes to arcanum are documented here.

## [0.1.0] — 2026-03-13

Initial release of arcanum, a pure-Python RSA library and drop-in replacement for the archived `python-rsa` package.

### Added

- **Core math** — modular exponentiation, inverse, CRT, GCD primitives; always-on RSA blinding to prevent timing side-channels
- **Prime generation** — Miller-Rabin primality testing, random prime generation
- **Key generation** — RSA key pair generation (512–4096+ bit), configurable public exponent
- **Key serialization** — PKCS#1 and PKCS#8 private key formats, PEM and DER encoding/decoding
- **Parallel key generation** — multiprocessing-based key pair generation for faster results
- **PKCS#1 v1.5** — encrypt, decrypt (constant-time padding validation), sign, and verify with SHA-1 through SHA-512
- **OAEP (PKCS#1 v2.1)** — encrypt and decrypt with configurable hash algorithm and MGF; timing-hardened implementation
- **python-rsa compatibility shim** — `import arcanum as rsa` works as a drop-in replacement; `compat.py` re-exports the full `rsa` public API
- **Cross-verification test suite** — round-trip tests against `python-rsa` to confirm wire compatibility
- **Typed** — fully annotated, passes `mypy --strict`; ships `py.typed` marker (PEP 561)
- **CI** — GitHub Actions matrix across Python 3.9–3.13 and PyPy 3.10; ruff lint and mypy typecheck

### Security

- OAEP implementation avoids early-exit branches on padding errors (timing leak fix)
- PKCS#1 v1.5 decrypt uses constant-time padding comparison
- PKCS#8 OID and BIT STRING validation hardened
- Hash length validation per RFC 8017
- MD5 signing not supported (unlike python-rsa)
