"""
Coinnectar Core Module

Defines base exceptions, data envelopes, and high-level message packaging protocols
for secure fintech data exchange.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Dict, Optional, Union

from coinnectar.crypto import (
    constant_time_compare,
    generate_nonce,
    sign_payload,
)
from coinnectar.utils import current_timestamp


class CoinnectarError(Exception):
    """Base exception class for all Coinnectar errors."""


class SerializationError(CoinnectarError):
    """Raised when serialization or deserialization encounters corrupt or invalid data."""


class VersionMismatchError(SerializationError):
    """Raised when the serialized protocol version is unsupported by the runtime."""


class IntegrityError(CoinnectarError):
    """Raised when data integrity validation (CRC32, HMAC) fails."""


class SecurityError(CoinnectarError):
    """Raised when a security constraint (timestamp expiration, replay) is violated."""


@dataclasses.dataclass
class Envelope:
    """
    Standard message envelope for authenticating and exchanging structured data.

    Envelopes bundle the core payload with metadata, unique nonce identifiers,
    timestamps, and an optional HMAC signature.
    """

    data: Any
    payload_id: str = dataclasses.field(default_factory=lambda: generate_nonce(16))
    created_at: int = dataclasses.field(default_factory=current_timestamp)
    version: int = 1
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)
    signature: Optional[str] = None

    def _canonical_bytes(self) -> bytes:
        """
        Serialize envelope headers and data into a deterministic byte string for signing.
        """
        from coinnectar.serialize import dumps

        canonical_dict = {
            "payload_id": self.payload_id,
            "created_at": self.created_at,
            "version": self.version,
            "metadata": self.metadata,
            "data": self.data,
        }
        return dumps(canonical_dict)

    def sign(self, key: bytes, digestmod: str = "sha256") -> Envelope:
        """
        Compute an HMAC signature over the envelope contents and record it in hex.

        Args:
            key: Secret symmetric key for HMAC calculation.
            digestmod: Hashing algorithm (default: "sha256").

        Returns:
            Self (mutated with updated signature).
        """
        raw_canonical = self._canonical_bytes()
        digest = sign_payload(raw_canonical, key, digestmod=digestmod)
        self.signature = digest.hex()
        return self

    def verify(
        self,
        key: bytes,
        max_age_seconds: Optional[int] = None,
        clock_skew_tolerance: int = 60,
        digestmod: str = "sha256",
    ) -> bool:
        """
        Verify envelope HMAC signature and ensure timestamp has not expired.

        Args:
            key: Secret symmetric key used for HMAC verification.
            max_age_seconds: Optional maximum allowed age of payload in seconds.
            clock_skew_tolerance: Allowed clock drift for future timestamps in seconds (default: 60).
            digestmod: Hashing algorithm (default: "sha256").

        Returns:
            True if signature and timestamp checks pass.

        Raises:
            SecurityError: If envelope is unsigned or has expired.
            IntegrityError: If signature fails validation.
        """
        if not self.signature:
            raise SecurityError("Envelope is not signed")

        # Validate timestamp freshness if max_age_seconds is set
        now = current_timestamp()
        if max_age_seconds is not None:
            if self.created_at > (now + clock_skew_tolerance):
                raise SecurityError(
                    f"Envelope created_at ({self.created_at}) is too far in the future (skew: {self.created_at - now}s)"
                )
            if (now - self.created_at) > max_age_seconds:
                raise SecurityError(
                    f"Envelope expired: age {now - self.created_at}s exceeds limit of {max_age_seconds}s"
                )

        raw_canonical = self._canonical_bytes()
        expected = sign_payload(raw_canonical, key, digestmod=digestmod)

        try:
            actual = bytes.fromhex(self.signature)
        except (ValueError, TypeError) as exc:
            raise IntegrityError("Corrupted signature format: invalid hex") from exc

        if not constant_time_compare(actual, expected):
            raise IntegrityError(
                f"Envelope signature verification failed for payload_id={self.payload_id!r}"
            )

        return True

    def to_dict(self) -> Dict[str, Any]:
        """Convert Envelope to a primitive dictionary."""
        return {
            "payload_id": self.payload_id,
            "created_at": self.created_at,
            "version": self.version,
            "metadata": self.metadata,
            "signature": self.signature,
            "data": self.data,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Envelope:
        """Construct an Envelope instance from a dictionary."""
        return cls(
            payload_id=str(data.get("payload_id", "")),
            created_at=int(data.get("created_at", 0)),
            version=int(data.get("version", 1)),
            metadata=dict(data.get("metadata", {})),
            signature=data.get("signature"),
            data=data.get("data"),
        )

    def pack(self, secret_key: Optional[bytes] = None) -> bytes:
        """
        Pack envelope into binary Coinnectar wire format, optionally signing first.

        Args:
            secret_key: If provided, envelope is signed before serialization.

        Returns:
            Serialized binary payload.
        """
        from coinnectar.serialize import dumps

        if secret_key is not None:
            self.sign(secret_key)
        return dumps(self.to_dict())

    @classmethod
    def unpack(
        cls,
        raw: bytes,
        secret_key: Optional[bytes] = None,
        max_age_seconds: Optional[int] = None,
    ) -> Envelope:
        """
        Unpack binary wire bytes into an Envelope, optionally verifying authenticity.

        Args:
            raw: Serialized Coinnectar payload.
            secret_key: If provided, verifies envelope signature.
            max_age_seconds: Maximum allowed age in seconds if secret_key is supplied.

        Returns:
            Decoded Envelope instance.

        Raises:
            SerializationError: If byte data cannot be parsed.
            IntegrityError: If signature fails validation.
            SecurityError: If envelope is expired or unsigned.
        """
        from coinnectar.serialize import loads

        parsed = loads(raw)
        if not isinstance(parsed, dict):
            raise SerializationError("Decoded payload is not a valid Envelope mapping")

        envelope = cls.from_dict(parsed)
        if secret_key is not None:
            envelope.verify(secret_key, max_age_seconds=max_age_seconds)

        return envelope


def pack_envelope(
    data: Any,
    secret_key: Optional[bytes] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> bytes:
    """
    Convenience wrapper to construct, sign, and pack an Envelope in one call.
    """
    env = Envelope(data=data, metadata=metadata or {})
    return env.pack(secret_key=secret_key)


def unpack_envelope(
    raw: bytes,
    secret_key: Optional[bytes] = None,
    max_age_seconds: Optional[int] = None,
) -> Envelope:
    """
    Convenience wrapper to unpack and optionally verify an Envelope in one call.
    """
    return Envelope.unpack(raw, secret_key=secret_key, max_age_seconds=max_age_seconds)
