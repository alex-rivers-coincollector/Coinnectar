"""
Coinnectar Cryptographic Primitives

Provides constant-time comparison, HMAC authentication, key derivation (PBKDF2),
secure token generation, and wire stream masking.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Union

try:
    from coinnectar import _native  # type: ignore
    _HAS_NATIVE_CRYPTO = (
        hasattr(_native, "constant_time_compare") and hasattr(_native, "xor_mask")
    )
except ImportError:
    _native = None
    _HAS_NATIVE_CRYPTO = False


def constant_time_compare(val1: Union[bytes, bytearray], val2: Union[bytes, bytearray]) -> bool:
    """
    Compare two byte buffers in constant time to prevent side-channel timing attacks.

    Delegates to compiled C extension if present; otherwise uses Python's hmac.compare_digest.

    Args:
        val1: First byte buffer.
        val2: Second byte buffer.

    Returns:
        True if buffers match exactly, False otherwise.
    """
    if _HAS_NATIVE_CRYPTO and _native is not None:
        try:
            return bool(_native.constant_time_compare(bytes(val1), bytes(val2)))
        except (TypeError, ValueError):
            return False

    return hmac.compare_digest(bytes(val1), bytes(val2))


def xor_mask(data: bytes, key: bytes) -> bytes:
    """
    Apply symmetric XOR masking over data with a repeating secret key.

    Useful for lightweight obfuscation and frame-masking on wire protocols.

    Args:
        data: Raw input bytes.
        key: Key bytes used to mask/unmask (must not be empty).

    Returns:
        Masked byte sequence.

    Raises:
        ValueError: If key is empty.
    """
    if not key:
        raise ValueError("XOR masking key cannot be empty")

    if _HAS_NATIVE_CRYPTO and _native is not None:
        return _native.xor_mask(data, key)

    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


def generate_key(length: int = 32) -> bytes:
    """
    Generate cryptographically secure pseudo-random bytes.

    Args:
        length: Number of bytes to generate (default: 32 bytes / 256 bits).

    Returns:
        Random byte sequence.

    Raises:
        ValueError: If length is less than 1.
    """
    if length < 1:
        raise ValueError("Key length must be at least 1 byte")
    return secrets.token_bytes(length)


def generate_nonce(length: int = 16) -> str:
    """
    Generate a cryptographically secure random hexadecimal nonce.

    Args:
        length: Number of random bytes underlying the nonce (default: 16 bytes / 32 hex chars).

    Returns:
        Hexadecimal string token.

    Raises:
        ValueError: If length is less than 1.
    """
    if length < 1:
        raise ValueError("Nonce length must be at least 1 byte")
    return secrets.token_hex(length)


def derive_key(
    secret: bytes,
    salt: bytes,
    length: int = 32,
    iterations: int = 100_000,
    hash_name: str = "sha256",
) -> bytes:
    """
    Derive a cryptographic subkey from a master secret and salt using PBKDF2-HMAC.

    Args:
        secret: Master secret passphrase or key bytes.
        salt: Unique salt bytes (at least 16 bytes recommended).
        length: Derived key size in bytes (default: 32).
        iterations: Number of PBKDF2 hashing rounds (default: 100,000).
        hash_name: Inner hash algorithm name (default: "sha256").

    Returns:
        Derived subkey bytes.

    Raises:
        ValueError: If parameters are invalid or iterations < 1000.
    """
    if not secret:
        raise ValueError("Secret cannot be empty")
    if not salt:
        raise ValueError("Salt cannot be empty")
    if length < 1:
        raise ValueError("Derived key length must be positive")
    if iterations < 1000:
        raise ValueError("Iteration count must be at least 1,000 for security")

    return hashlib.pbkdf2_hmac(hash_name, secret, salt, iterations, dklen=length)


def sign_payload(data: bytes, key: bytes, digestmod: str = "sha256") -> bytes:
    """
    Compute an HMAC authentication tag over arbitrary binary payload.

    Args:
        data: Binary payload to authenticate.
        key: Secret symmetric authentication key.
        digestmod: Hash algorithm name (default: "sha256").

    Returns:
        Raw binary HMAC digest.

    Raises:
        ValueError: If key is empty.
    """
    if not key:
        raise ValueError("Signing key cannot be empty")

    return hmac.new(key, data, digestmod).digest()


def verify_payload(
    data: bytes,
    key: bytes,
    expected_signature: bytes,
    digestmod: str = "sha256",
) -> bool:
    """
    Verify an HMAC authentication tag against payload using constant-time comparison.

    Args:
        data: Binary payload that was authenticated.
        key: Secret symmetric authentication key.
        expected_signature: The received signature bytes to check.
        digestmod: Hash algorithm name (default: "sha256").

    Returns:
        True if signature is valid and payload intact, False otherwise.
    """
    if not key or not expected_signature:
        return False

    computed = sign_payload(data, key, digestmod)
    return constant_time_compare(computed, expected_signature)
