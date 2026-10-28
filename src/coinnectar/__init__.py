"""
Coinnectar: Secure Data Serialization & Basic Cryptographic Primitives

Coinnectar is a lightweight, high-performance library engineered for secure
data serialization and cryptographic message integrity in fintech services,
transaction brokers, and internal infrastructure.

Maintained by Elias Varga and a small group of contributors.
"""

from __future__ import annotations

__version__ = "0.8.2"
__author__ = "Elias Varga and Coinnectar Contributors"
__license__ = "MIT"
__copyright__ = "Copyright (c) 2020-2025 Elias Varga and Coinnectar Contributors"

from coinnectar.core import (
    CoinnectarError,
    Envelope,
    IntegrityError,
    SecurityError,
    SerializationError,
    VersionMismatchError,
    pack_envelope,
    unpack_envelope,
)
from coinnectar.crypto import (
    constant_time_compare,
    derive_key,
    generate_key,
    generate_nonce,
    sign_payload,
    verify_payload,
    xor_mask,
)
from coinnectar.serialize import (
    Serializer,
    dump,
    dumps,
    load,
    loads,
)
from coinnectar.utils import (
    crc32_checksum,
    current_timestamp,
    pkcs7_pad,
    pkcs7_unpad,
    safe_hex_digest,
    validate_byte_length,
)

__all__ = [
    # Metadata
    "__version__",
    "__author__",
    "__license__",
    "__copyright__",
    # Core exceptions
    "CoinnectarError",
    "SerializationError",
    "VersionMismatchError",
    "IntegrityError",
    "SecurityError",
    # Core types & envelopes
    "Envelope",
    "pack_envelope",
    "unpack_envelope",
    # Serialization
    "Serializer",
    "dumps",
    "loads",
    "dump",
    "load",
    # Cryptographic primitives
    "constant_time_compare",
    "sign_payload",
    "verify_payload",
    "generate_key",
    "generate_nonce",
    "derive_key",
    "xor_mask",
    # Utilities
    "crc32_checksum",
    "pkcs7_pad",
    "pkcs7_unpad",
    "safe_hex_digest",
    "current_timestamp",
    "validate_byte_length",
]
