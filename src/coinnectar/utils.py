"""
Coinnectar Utilities Module

Provides helper utilities for checksum calculation, padding, data validation,
and timestamping across serialization and cryptographic pipelines.
"""

from __future__ import annotations

import time
import zlib
from typing import Optional

try:
    from coinnectar import _native  # type: ignore
    _HAS_NATIVE_CRC = hasattr(_native, "crc32")
except ImportError:
    _native = None
    _HAS_NATIVE_CRC = False


def crc32_checksum(data: bytes) -> int:
    """
    Calculate 32-bit CRC (IEEE 802.3 standard) over input bytes.

    Uses native C acceleration if available; otherwise falls back to standard zlib.

    Args:
        data: Raw byte sequence to hash.

    Returns:
        Unsigned 32-bit integer checksum.
    """
    if _HAS_NATIVE_CRC and _native is not None:
        return _native.crc32(data)
    # zlib.crc32 returns an unsigned 32-bit int in Python 3
    return zlib.crc32(data) & 0xFFFFFFFF


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """
    Pad a byte sequence using standard PKCS#7 padding.

    Args:
        data: Unpadded byte payload.
        block_size: Cipher block size in bytes (must be between 1 and 255, default 16).

    Returns:
        Padded byte payload.

    Raises:
        ValueError: If block_size is outside the valid range [1, 255].
    """
    if not (1 <= block_size <= 255):
        raise ValueError(f"Block size must be between 1 and 255 (got {block_size})")

    padding_len = block_size - (len(data) % block_size)
    padding_bytes = bytes([padding_len]) * padding_len
    return data + padding_bytes


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    """
    Remove PKCS#7 padding from a byte sequence.

    Args:
        data: Padded byte payload.
        block_size: Cipher block size in bytes (default 16).

    Returns:
        Original unpadded bytes.

    Raises:
        ValueError: If padding is invalid, corrupted, or does not match block size.
    """
    if not data:
        raise ValueError("Cannot unpad empty byte sequence")

    if len(data) % block_size != 0:
        raise ValueError(
            f"Data length ({len(data)}) is not a multiple of block size ({block_size})"
        )

    padding_len = data[-1]
    if padding_len == 0 or padding_len > block_size:
        raise ValueError(f"Invalid PKCS#7 padding byte: {padding_len}")

    expected_padding = bytes([padding_len]) * padding_len
    if data[-padding_len:] != expected_padding:
        raise ValueError("Corrupt PKCS#7 padding sequence")

    return data[:-padding_len]


def safe_hex_digest(data: bytes) -> str:
    """
    Convert a byte sequence to a lowercase hexadecimal string safely.

    Args:
        data: Byte buffer to encode.

    Returns:
        Hexadecimal string.
    """
    return data.hex()


def current_timestamp() -> int:
    """
    Return the current system time as a UTC unix timestamp in seconds.
    """
    return int(time.time())


def validate_byte_length(
    data: bytes,
    min_len: Optional[int] = None,
    max_len: Optional[int] = None,
    name: str = "buffer",
) -> None:
    """
    Enforce byte boundary validation to prevent buffer overflows or truncation attacks.

    Args:
        data: Buffer to validate.
        min_len: Minimum allowed length (inclusive).
        max_len: Maximum allowed length (inclusive).
        name: Name of buffer for error messages.

    Raises:
        TypeError: If data is not bytes or bytearray.
        ValueError: If buffer size is out of bounds.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be a bytes-like object, got {type(data).__name__}")

    length = len(data)
    if min_len is not None and length < min_len:
        raise ValueError(
            f"{name} length ({length} bytes) is below minimum required length ({min_len} bytes)"
        )
    if max_len is not None and length > max_len:
        raise ValueError(
            f"{name} length ({length} bytes) exceeds maximum permitted length ({max_len} bytes)"
        )
