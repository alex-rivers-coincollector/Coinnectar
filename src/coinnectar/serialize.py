"""
Coinnectar Binary Serialization Protocol

Provides fast, compact, and validated binary serialization for fintech message payloads.
Includes wire-header integrity validation, recursion protection, and CRC32 verification.
"""

from __future__ import annotations

import io
import struct
from typing import Any, BinaryIO, Dict, List, Optional, Tuple

from coinnectar.core import (
    IntegrityError,
    SerializationError,
    VersionMismatchError,
)
from coinnectar.utils import crc32_checksum

try:
    from coinnectar import _native  # type: ignore
    _HAS_NATIVE = hasattr(_native, "fast_validate_header")
except ImportError:
    _native = None
    _HAS_NATIVE = False

# Protocol Wire Constants
MAGIC: bytes = b"CNCT"
MAGIC_U32: int = 0x434E4354
PROTOCOL_VERSION: int = 1
HEADER_SIZE: int = 14
DEFAULT_MAX_PAYLOAD_SIZE: int = 64 * 1024 * 1024  # 64 MB
DEFAULT_MAX_RECURSION_DEPTH: int = 128

# Type Tags
TAG_NULL: int = 0x00
TAG_BOOL_FALSE: int = 0x01
TAG_BOOL_TRUE: int = 0x02
TAG_INT64: int = 0x03
TAG_FLOAT64: int = 0x04
TAG_BYTES: int = 0x05
TAG_STRING: int = 0x06
TAG_LIST: int = 0x07
TAG_DICT: int = 0x08


class Serializer:
    """
    Configurable binary serializer and deserializer for Coinnectar wire format.
    """

    def __init__(
        self,
        max_payload_size: int = DEFAULT_MAX_PAYLOAD_SIZE,
        max_recursion_depth: int = DEFAULT_MAX_RECURSION_DEPTH,
    ) -> None:
        self.max_payload_size = max_payload_size
        self.max_recursion_depth = max_recursion_depth

    def _pack_value(self, obj: Any, buf: io.BytesIO, depth: int) -> None:
        if depth > self.max_recursion_depth:
            raise SerializationError(
                f"Maximum recursion depth ({self.max_recursion_depth}) exceeded during serialization"
            )

        if obj is None:
            buf.write(bytes([TAG_NULL]))
        elif isinstance(obj, bool):
            buf.write(bytes([TAG_BOOL_TRUE if obj else TAG_BOOL_FALSE]))
        elif isinstance(obj, int):
            # Check 64-bit integer range
            if not (-9223372036854775808 <= obj <= 9223372036854775807):
                raise SerializationError(f"Integer {obj} out of 64-bit range")
            buf.write(bytes([TAG_INT64]))
            buf.write(struct.pack(">q", obj))
        elif isinstance(obj, float):
            buf.write(bytes([TAG_FLOAT64]))
            buf.write(struct.pack(">d", obj))
        elif isinstance(obj, (bytes, bytearray, memoryview)):
            raw_bytes = bytes(obj)
            buf.write(bytes([TAG_BYTES]))
            buf.write(struct.pack(">I", len(raw_bytes)))
            buf.write(raw_bytes)
        elif isinstance(obj, str):
            encoded = obj.encode("utf-8")
            buf.write(bytes([TAG_STRING]))
            buf.write(struct.pack(">I", len(encoded)))
            buf.write(encoded)
        elif isinstance(obj, (list, tuple)):
            buf.write(bytes([TAG_LIST]))
            buf.write(struct.pack(">I", len(obj)))
            for item in obj:
                self._pack_value(item, buf, depth + 1)
        elif isinstance(obj, dict):
            buf.write(bytes([TAG_DICT]))
            buf.write(struct.pack(">I", len(obj)))
            # Sort keys for deterministic output if all string keys
            keys = sorted(obj.keys()) if all(isinstance(k, str) for k in obj.keys()) else list(obj.keys())
            for key in keys:
                self._pack_value(key, buf, depth + 1)
                self._pack_value(obj[key], buf, depth + 1)
        else:
            raise SerializationError(
                f"Unsupported type for Coinnectar serialization: {type(obj).__name__}"
            )

    def _unpack_value(self, reader: io.BytesIO, depth: int) -> Any:
        if depth > self.max_recursion_depth:
            raise SerializationError(
                f"Maximum recursion depth ({self.max_recursion_depth}) exceeded during deserialization"
            )

        tag_byte = reader.read(1)
        if not tag_byte:
            raise SerializationError("Unexpected EOF while reading type tag")

        tag = tag_byte[0]
        if tag == TAG_NULL:
            return None
        elif tag == TAG_BOOL_FALSE:
            return False
        elif tag == TAG_BOOL_TRUE:
            return True
        elif tag == TAG_INT64:
            data = reader.read(8)
            if len(data) < 8:
                raise SerializationError("Truncated int64 value")
            return struct.unpack(">q", data)[0]
        elif tag == TAG_FLOAT64:
            data = reader.read(8)
            if len(data) < 8:
                raise SerializationError("Truncated float64 value")
            return struct.unpack(">d", data)[0]
        elif tag == TAG_BYTES:
            len_bytes = reader.read(4)
            if len(len_bytes) < 4:
                raise SerializationError("Truncated bytes length prefix")
            length = struct.unpack(">I", len_bytes)[0]
            if length > self.max_payload_size:
                raise SerializationError(f"Bytes segment length {length} exceeds maximum allowed size")
            val = reader.read(length)
            if len(val) < length:
                raise SerializationError(f"Premature EOF: expected {length} bytes, got {len(val)}")
            return val
        elif tag == TAG_STRING:
            len_bytes = reader.read(4)
            if len(len_bytes) < 4:
                raise SerializationError("Truncated string length prefix")
            length = struct.unpack(">I", len_bytes)[0]
            if length > self.max_payload_size:
                raise SerializationError(f"String length {length} exceeds maximum allowed size")
            val = reader.read(length)
            if len(val) < length:
                raise SerializationError(f"Premature EOF: expected {length} string bytes, got {len(val)}")
            try:
                return val.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise SerializationError(f"Invalid UTF-8 payload: {exc}") from exc
        elif tag == TAG_LIST:
            count_bytes = reader.read(4)
            if len(count_bytes) < 4:
                raise SerializationError("Truncated list count prefix")
            count = struct.unpack(">I", count_bytes)[0]
            items: List[Any] = []
            for _ in range(count):
                items.append(self._unpack_value(reader, depth + 1))
            return items
        elif tag == TAG_DICT:
            count_bytes = reader.read(4)
            if len(count_bytes) < 4:
                raise SerializationError("Truncated dict count prefix")
            count = struct.unpack(">I", count_bytes)[0]
            res: Dict[Any, Any] = {}
            for _ in range(count):
                k = self._unpack_value(reader, depth + 1)
                v = self._unpack_value(reader, depth + 1)
                res[k] = v
            return res
        else:
            raise SerializationError(f"Unknown or invalid type tag: 0x{tag:02x}")

    def serialize(self, obj: Any, flags: int = 0) -> bytes:
        """
        Serialize a Python object into Coinnectar wire format bytes.
        """
        body_buf = io.BytesIO()
        self._pack_value(obj, body_buf, depth=0)
        body = body_buf.getvalue()

        if len(body) > self.max_payload_size:
            raise SerializationError(
                f"Payload size ({len(body)} bytes) exceeds configured maximum ({self.max_payload_size} bytes)"
            )

        crc = crc32_checksum(body)
        header = struct.pack(">4sBBI I", MAGIC, PROTOCOL_VERSION, flags, crc, len(body))
        return header + body

    def deserialize(self, raw: bytes) -> Any:
        """
        Deserialize Coinnectar wire format bytes back into a Python object.
        """
        if len(raw) < HEADER_SIZE:
            raise SerializationError(
                f"Input buffer ({len(raw)} bytes) is smaller than Coinnectar header ({HEADER_SIZE} bytes)"
            )

        # Fast path via C extension if compiled
        if _HAS_NATIVE and _native is not None:
            try:
                version, flags, crc, length = _native.fast_validate_header(raw)
            except ValueError as exc:
                msg = str(exc)
                if "magic" in msg:
                    raise SerializationError(msg) from exc
                elif "Checksum" in msg or "checksum" in msg:
                    raise IntegrityError(msg) from exc
                elif "version" in msg or "Version" in msg:
                    raise VersionMismatchError(msg) from exc
                else:
                    raise SerializationError(msg) from exc

            if version != PROTOCOL_VERSION:
                raise VersionMismatchError(
                    f"Unsupported protocol version {version} (expected {PROTOCOL_VERSION})"
                )
        else:
            # Pure Python header parsing and validation
            magic, version, flags, crc, length = struct.unpack(">4sBBI I", raw[:HEADER_SIZE])
            if magic != MAGIC:
                raise SerializationError(f"Invalid Coinnectar magic signature: {magic!r}")
            if version != PROTOCOL_VERSION:
                raise VersionMismatchError(
                    f"Unsupported protocol version {version} (expected {PROTOCOL_VERSION})"
                )
            if length > self.max_payload_size:
                raise SerializationError(
                    f"Payload size ({length} bytes) exceeds limit ({self.max_payload_size} bytes)"
                )
            if len(raw) < HEADER_SIZE + length:
                raise SerializationError(
                    f"Incomplete payload: expected {length} bytes, received {len(raw) - HEADER_SIZE}"
                )

            body = raw[HEADER_SIZE : HEADER_SIZE + length]
            calculated_crc = crc32_checksum(body)
            if calculated_crc != crc:
                raise IntegrityError(
                    f"Checksum mismatch: header CRC=0x{crc:08X}, calculated CRC=0x{calculated_crc:08X}"
                )

        body = raw[HEADER_SIZE : HEADER_SIZE + length]
        reader = io.BytesIO(body)
        result = self._unpack_value(reader, depth=0)

        # Ensure entire body was consumed
        remaining = reader.read()
        if remaining:
            raise SerializationError(f"Trailing unconsumed bytes in payload: {len(remaining)} bytes")

        return result


_DEFAULT_SERIALIZER = Serializer()


def dumps(obj: Any) -> bytes:
    """
    Serialize an object into Coinnectar binary format.
    """
    return _DEFAULT_SERIALIZER.serialize(obj)


def loads(data: bytes, max_size: int = DEFAULT_MAX_PAYLOAD_SIZE) -> Any:
    """
    Deserialize Coinnectar binary format bytes into a Python object.
    """
    if max_size != DEFAULT_MAX_PAYLOAD_SIZE:
        serializer = Serializer(max_payload_size=max_size)
        return serializer.deserialize(data)
    return _DEFAULT_SERIALIZER.deserialize(data)


def dump(obj: Any, fp: BinaryIO) -> None:
    """
    Serialize an object directly into a binary stream.
    """
    fp.write(dumps(obj))


def load(fp: BinaryIO, max_size: int = DEFAULT_MAX_PAYLOAD_SIZE) -> Any:
    """
    Read and deserialize an object from a binary stream.
    """
    header_bytes = fp.read(HEADER_SIZE)
    if len(header_bytes) < HEADER_SIZE:
        raise SerializationError("Incomplete header in stream")

    # Read length from header (bytes 10..14)
    length = struct.unpack(">I", header_bytes[10:14])[0]
    if length > max_size:
        raise SerializationError(f"Stream payload size {length} exceeds maximum {max_size}")

    body_bytes = fp.read(length)
    if len(body_bytes) < length:
        raise SerializationError(
            f"Stream ended prematurely: expected {length} bytes, got {len(body_bytes)}"
        )

    return loads(header_bytes + body_bytes, max_size=max_size)
