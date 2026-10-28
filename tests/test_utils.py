"""
Unit tests for Coinnectar utility functions.
"""

import os
import sys
import unittest

# Ensure src/ is on sys.path for test runner execution
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from coinnectar.utils import (
    crc32_checksum,
    current_timestamp,
    pkcs7_pad,
    pkcs7_unpad,
    safe_hex_digest,
    validate_byte_length,
)


class TestUtils(unittest.TestCase):
    """Test general utility routines: checksums, padding, and validations."""

    def test_crc32_known_vector(self):
        # Standard IEEE 802.3 test vector: "123456789" -> 0xCBF43926 (3421780262)
        vector = b"123456789"
        expected = 0xCBF43926
        self.assertEqual(crc32_checksum(vector), expected)

    def test_crc32_empty(self):
        self.assertEqual(crc32_checksum(b""), 0)

    def test_pkcs7_pad_unpad_roundtrip(self):
        cases = [
            b"",
            b"test",
            b"123456789012345",  # 15 bytes (1 byte padding needed)
            b"1234567890123456",  # 16 bytes (full block of 16 padding needed)
            b"arbitrary longer stream data of varying byte lengths",
        ]
        for data in cases:
            with self.subTest(data=data):
                padded = pkcs7_pad(data, block_size=16)
                self.assertEqual(len(padded) % 16, 0)
                unpadded = pkcs7_unpad(padded, block_size=16)
                self.assertEqual(unpadded, data)

    def test_pkcs7_invalid_block_size(self):
        with self.assertRaises(ValueError):
            pkcs7_pad(b"data", block_size=0)
        with self.assertRaises(ValueError):
            pkcs7_pad(b"data", block_size=256)

    def test_pkcs7_corrupt_padding(self):
        # Empty data
        with self.assertRaises(ValueError):
            pkcs7_unpad(b"")

        # Length not multiple of block size
        with self.assertRaises(ValueError):
            pkcs7_unpad(b"12345", block_size=16)

        # Padding byte says 4, but tail bytes are not all 0x04
        bad_pad = b"123456789012\x04\x04\x01\x04"
        with self.assertRaises(ValueError):
            pkcs7_unpad(bad_pad, block_size=16)

        # Padding byte is 0
        zero_pad = b"123456789012345\x00"
        with self.assertRaises(ValueError):
            pkcs7_unpad(zero_pad, block_size=16)

    def test_safe_hex_digest(self):
        self.assertEqual(safe_hex_digest(b"\x00\x0a\xff"), "000aff")
        self.assertEqual(safe_hex_digest(b""), "")

    def test_current_timestamp(self):
        ts = current_timestamp()
        self.assertIsInstance(ts, int)
        self.assertGreater(ts, 1600000000)

    def test_validate_byte_length(self):
        # Valid cases
        validate_byte_length(b"12345", min_len=1, max_len=10)
        validate_byte_length(b"exact", min_len=5, max_len=5)

        # Too short
        with self.assertRaises(ValueError):
            validate_byte_length(b"short", min_len=10)

        # Too long
        with self.assertRaises(ValueError):
            validate_byte_length(b"way too long buffer", max_len=5)

        # Invalid type
        with self.assertRaises(TypeError):
            validate_byte_length("not bytes", min_len=1)  # type: ignore


if __name__ == "__main__":
    unittest.main()
