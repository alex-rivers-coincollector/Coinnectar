"""
Unit tests for Coinnectar cryptographic primitives.
"""

import os
import sys
import unittest

# Ensure src/ is on sys.path for test runner execution
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from coinnectar.core import IntegrityError
from coinnectar.crypto import (
    constant_time_compare,
    derive_key,
    encrypt_then_mac,
    generate_key,
    generate_nonce,
    mac_then_decrypt,
    sign_payload,
    verify_payload,
    xor_mask,
)


class TestCryptoPrimitives(unittest.TestCase):
    """Test cryptographic functions and side-channel protections."""

    def test_constant_time_compare_equal(self):
        buf1 = b"secure_hash_digest_123456789012"
        buf2 = b"secure_hash_digest_123456789012"
        self.assertTrue(constant_time_compare(buf1, buf2))
        self.assertTrue(constant_time_compare(b"", b""))

    def test_constant_time_compare_unequal(self):
        buf1 = b"secure_hash_digest_123456789012"
        buf2 = b"secure_hash_digest_123456789013"
        self.assertFalse(constant_time_compare(buf1, buf2))

    def test_constant_time_compare_different_lengths(self):
        buf1 = b"abc"
        buf2 = b"abcd"
        self.assertFalse(constant_time_compare(buf1, buf2))

    def test_generate_key(self):
        key32 = generate_key(32)
        key64 = generate_key(64)
        self.assertEqual(len(key32), 32)
        self.assertEqual(len(key64), 64)
        self.assertNotEqual(key32, generate_key(32))

        with self.assertRaises(ValueError):
            generate_key(0)

    def test_generate_nonce(self):
        nonce1 = generate_nonce(16)
        nonce2 = generate_nonce(16)
        self.assertEqual(len(nonce1), 32)  # 16 bytes = 32 hex chars
        self.assertNotEqual(nonce1, nonce2)
        # Verify valid hex
        int(nonce1, 16)

        with self.assertRaises(ValueError):
            generate_nonce(-1)

    def test_derive_key_deterministic(self):
        secret = b"ledger-master-key-phrase"
        salt = b"salt-12345678-salt"
        key1 = derive_key(secret, salt, length=32, iterations=1000)
        key2 = derive_key(secret, salt, length=32, iterations=1000)
        self.assertEqual(key1, key2)
        self.assertEqual(len(key1), 32)

    def test_derive_key_uniqueness(self):
        secret = b"ledger-master-key-phrase"
        salt1 = b"salt-11111111-salt"
        salt2 = b"salt-22222222-salt"
        key1 = derive_key(secret, salt1, length=32, iterations=1000)
        key2 = derive_key(secret, salt2, length=32, iterations=1000)
        self.assertNotEqual(key1, key2)

    def test_derive_key_validation(self):
        with self.assertRaises(ValueError):
            derive_key(b"", b"salt")
        with self.assertRaises(ValueError):
            derive_key(b"secret", b"")
        with self.assertRaises(ValueError):
            derive_key(b"secret", b"salt", iterations=500)

    def test_sign_and_verify_payload(self):
        key = b"bank-internal-signing-key-32b!"
        message = b"TRANSFER $10,000 FROM ACC-1 TO ACC-2"

        signature = sign_payload(message, key)
        self.assertEqual(len(signature), 32)  # SHA-256 = 32 bytes

        # Valid signature
        self.assertTrue(verify_payload(message, key, signature))

        # Tampered message
        tampered = b"TRANSFER $90,000 FROM ACC-1 TO ACC-2"
        self.assertFalse(verify_payload(tampered, key, signature))

        # Tampered signature
        bad_sig = bytearray(signature)
        bad_sig[0] ^= 0xFF
        self.assertFalse(verify_payload(message, key, bytes(bad_sig)))

        # Different key
        wrong_key = b"different-signing-key-32-bytes!"
        self.assertFalse(verify_payload(message, wrong_key, signature))

    def test_sign_payload_empty_key(self):
        with self.assertRaises(ValueError):
            sign_payload(b"data", b"")

    def test_xor_mask_roundtrip(self):
        data = b"sensitive settlement payload #9482918"
        key = b"stream-mask-key-xyz"

        masked = xor_mask(data, key)
        self.assertNotEqual(masked, data)

        unmasked = xor_mask(masked, key)
        self.assertEqual(unmasked, data)

    def test_xor_mask_empty_key(self):
        with self.assertRaises(ValueError):
            xor_mask(b"hello", b"")

    def test_encrypt_then_mac_roundtrip(self):
        enc_key = b"encryption-key-32-bytes-abcdefg!"
        mac_key = b"authentication-key-32-bytes-hijk!"
        plaintext = b"Transfer $50,000 to Account-998811"

        packet = encrypt_then_mac(plaintext, enc_key, mac_key)
        self.assertGreater(len(packet), 48)

        recovered = mac_then_decrypt(packet, enc_key, mac_key)
        self.assertEqual(recovered, plaintext)

    def test_encrypt_then_mac_tampering(self):
        enc_key = b"encryption-key-32-bytes-abcdefg!"
        mac_key = b"authentication-key-32-bytes-hijk!"
        plaintext = b"Confidential banking message"

        packet = bytearray(encrypt_then_mac(plaintext, enc_key, mac_key))

        # Tampering with ciphertext
        packet[-1] ^= 0x01
        with self.assertRaises(IntegrityError):
            mac_then_decrypt(bytes(packet), enc_key, mac_key)

        # Tampering with MAC tag
        packet[-1] ^= 0x01  # restore ciphertext
        packet[20] ^= 0x01   # corrupt MAC
        with self.assertRaises(IntegrityError):
            mac_then_decrypt(bytes(packet), enc_key, mac_key)

    def test_encrypt_then_mac_validation(self):
        with self.assertRaises(ValueError):
            encrypt_then_mac(b"data", b"", b"mac")
        with self.assertRaises(ValueError):
            mac_then_decrypt(b"short", b"enc", b"mac")


if __name__ == "__main__":
    unittest.main()
