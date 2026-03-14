"""PEM encoding and decoding.

Handles conversion between DER (binary) and PEM (base64-armored) formats
for RSA keys.
"""

import base64
import re

_PEM_HEADER_RE = re.compile(
    rb"-----BEGIN (.+?)-----\s*"
    rb"(.+?)"
    rb"\s*-----END \1-----",
    re.DOTALL,
)


def load_pem(contents: bytes) -> tuple[str, bytes]:
    """Decode a PEM-encoded block.

    Args:
        contents: The PEM-encoded data (e.g., the contents of a ``.pem`` file).

    Returns:
        A tuple of ``(marker, der_bytes)`` where *marker* is the text
        between ``BEGIN`` and ``END`` (e.g., ``"RSA PUBLIC KEY"``) and
        *der_bytes* is the decoded binary (DER) data.

    Raises:
        ValueError: If the PEM block cannot be parsed.
    """
    match = _PEM_HEADER_RE.search(contents)
    if match is None:
        raise ValueError("No PEM-encoded data found")

    marker = match.group(1).decode("ascii")
    base64_data = match.group(2)

    # Remove any whitespace from the base64 data
    base64_data = b"".join(base64_data.split())

    der_bytes = base64.standard_b64decode(base64_data)
    return marker, der_bytes


def save_pem(contents: bytes, marker: str) -> bytes:
    """Encode binary data as a PEM block.

    Args:
        contents: The binary (DER) data to encode.
        marker: The marker text (e.g., ``"RSA PUBLIC KEY"``).

    Returns:
        The PEM-encoded data with appropriate header and footer lines.
    """
    b64 = base64.standard_b64encode(contents).decode("ascii")

    # Wrap at 64 characters
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    wrapped = "\n".join(lines)

    pem = f"-----BEGIN {marker}-----\n{wrapped}\n-----END {marker}-----\n"
    return pem.encode("ascii")
