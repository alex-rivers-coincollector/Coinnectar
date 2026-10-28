"""
Unit tests for Coinnectar serialization and envelope packing.
"""

import io
import struct
import unittest
import sys
import os

# Ensure src/ is on sys.path for test runner execution
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from coinnectar import (
    dumps,
    loads,
    dump,
    load,
    Serializer,
    Envelope,
    pack_envelope,
    unpack_envelope,
    SerializationError,
    IntegrityError,
    VersionMismatchError,
    SecurityError,
)


class TestSerializePrimitives(unittest.TestCase):
    """Test serialization and deserialization of primitive Python data types."""

    def test_null(self):
        encoded = dumps(None)
        self.assertIsNone(loads(encoded))

    def test_booleans(self):
        self.assertIs(loads(dumps(True)), True)
        self.assertIs(loads(dumps(False)), False)

    def test_integers(self):
        cases = [0, 1, -1, 42, -999999, 2**31 - 1, -(2**31), 2**63 - 1, -(2**63)]
        for val in cases:
            with self.subTest(val=val):
                self.assertEqual(loads(dumps(val)), val)

    def test_integer_overflow(self):
        with self.assertRaises(SerializationError):
            dumps(2**64)

    def test_floats(self):
        cases = [0.0, -0.0, 3.141592653589793, -12345.6789, 1e-10, 1e10]
        for val in cases:
            with self.subTest(val=val):
                self.assertAlmostEqual(loads(dumps(val)), val, places=7)

    def test_bytes(self):
        cases = [b"", b"hello world", b"\x00\xff\xfe\x01\x10", bytes(range(256))]
        for val in cases:
            with self.subTest(val=val):
                self.assertEqual(loads(dumps(val)), val)

    def test_strings(self):
        cases = [
            "",
            "simple string",
            "fintech transfer: USD $1,250.00",
            "Unicode test: \u00e9, \u00e7, \u20ac, \u2602",
            "Emojis: \U0001f512\U0001f4b0\U0001f680",
        ]
        for val in cases:
            with self.subTest(val=val):
                self.assertEqual(loads(dumps(val)), val)


class TestSerializeComplex(unittest.TestCase):
    """Test serialization of compound structures (lists, dicts, nested objects)."""

    def test_empty_collections(self):
        self.assertEqual(loads(dumps([])), [])
        self.assertEqual(loads(dumps({})), {})

    def test_nested_list(self):
        payload = [1, "two", 3.0, [4, 5, ["nested", True, None]], b"bytes"]
        self.assertEqual(loads(dumps(payload)), payload)

    def test_nested_dict(self):
        payload = {
            "transaction_id": "tx-994829",
            "amount_cents": 125000,
            "currency": "EUR",
            "settled": True,
            "parties": {
                "source": "acc-1001",
                "destination": "acc-2002",
            },
            "tags": ["settlement", "instant", "tier-1"],
            "metadata": None,
        }
        self.assertEqual(loads(dumps(payload)), payload)

    def test_stream_dump_and_load(self):
        data = {"event": "ledger_entry", "id": 42}
        stream = io.BytesIO()
        dump(data, stream)
        stream.seek(0)
        loaded = load(stream)
        self.assertEqual(loaded, data)

    def test_unsupported_type(self):
        class CustomObj:
            pass

        with self.assertRaises(SerializationError):
            dumps(CustomObj())


class TestSerializationIntegrity(unittest.TestCase):
    """Test validation of headers, checksums, and corruption detection."""

    def test_corrupted_payload_triggers_integrity_error(self):
        raw = bytearray(dumps({"account": "A123", "balance": 1000}))
        # Tamper with the payload data (after 14 bytes header)
        raw[-1] ^= 0x01
        with self.assertRaises(IntegrityError):
            loads(bytes(raw))

    def test_invalid_magic_header(self):
        raw = bytearray(dumps({"valid": True}))
        # Corrupt the magic bytes 'CNCT'
        raw[0] = ord("X")
        with self.assertRaises(SerializationError):
            loads(bytes(raw))

    def test_truncated_header(self):
        raw = dumps("test")[:10]
        with self.assertRaises(SerializationError):
            loads(raw)

    def test_version_mismatch(self):
        raw = bytearray(dumps("test"))
        # Header layout: 4 magic, 1 version, 1 flags...
        raw[4] = 99  # Unsupported version
        # Fix CRC so it doesn't fail on checksum first
        body = raw[14:]
        from coinnectar.utils import crc32_checksum
        crc = crc32_checksum(body)
        raw[6:10] = struct.pack(">I", crc)

        with self.assertRaises(VersionMismatchError):
            loads(bytes(raw))

    def test_recursion_limit(self):
        serializer = Serializer(max_recursion_depth=5)
        deeply_nested: list = []
        curr = deeply_nested
        for _ in range(10):
            nxt: list = []
            curr.append(nxt)
            curr = nxt

        with self.assertRaises(SerializationError):
            serializer.serialize(deeply_nested)


class TestEnvelope(unittest.TestCase):
    """Test the high-level Envelope packaging and signing mechanisms."""

    def test_envelope_roundtrip_unsigned(self):
        data = {"user_id": 101, "role": "admin"}
        packed = pack_envelope(data, metadata={"client": "web-portal"})
        env = unpack_envelope(packed)
        self.assertEqual(env.data, data)
        self.assertEqual(env.metadata["client"], "web-portal")
        self.assertIsNotNone(env.payload_id)

    def test_envelope_signed_roundtrip(self):
        key = b"super-secret-key-32-bytes-long!"
        data = {"payment_id": "pay-8821", "amount": 540}
        packed = pack_envelope(data, secret_key=key)

        # Successful verification
        unpacked = unpack_envelope(packed, secret_key=key)
        self.assertEqual(unpacked.data, data)
        self.assertTrue(unpacked.signature)

        # Verification with incorrect key must fail
        with self.assertRaises(IntegrityError):
            unpack_envelope(packed, secret_key=b"wrong-key-32-bytes-long-padding!")

    def test_envelope_expiration(self):
        key = b"secret-key-for-expiration-test!"
        env = Envelope(data={"status": "ok"}, created_at=1000)
        env.sign(key)
        packed = env.pack()

        # Age is older than max_age_seconds
        with self.assertRaises(SecurityError):
            unpack_envelope(packed, secret_key=key, max_age_seconds=10)


if __name__ == "__main__":
    unittest.main()
