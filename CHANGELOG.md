# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.4.0] - 2024-10-25

### Added
- Protocol v2 versioned wire format with optional compression and authentication flags.
- Authenticated encryption helpers (`encrypt_then_mac`, `mac_then_decrypt`).
- C compatibility layer for wire header packing and unpacking.
- Multi-platform continuous integration testing matrix across Python 3.8–3.12 on Linux and Windows.
- High-throughput Redis event stream integration recipes in developer docs.

### Changed
- Vectorized 64-bit word chunking in C `cn_xor_mask` for high-throughput stream masking.
- Enhanced `SerializationError` and `IntegrityError` messages with byte offset diagnostics.
- Upgraded typing annotations to satisfy strict PEP 561 compliance.

## [1.0.0] - 2021-03-15

### Added
- Initial public release of Coinnectar.
- Compact Tag-Length-Value (TLV) binary serialization for Python primitives.
- Built-in IEEE 802.3 CRC32 wire header verification.
- Tamper-evident authenticated `Envelope` dataclass with HMAC-SHA256 signatures and timestamp validation.
- Constant-time memory comparison (`constant_time_compare`) to guard against side-channel timing attacks.
- Symmetric stream XOR masking helper (`xor_mask`).
- PBKDF2-HMAC-SHA256 subkey derivation helper (`derive_key`).
- PKCS#7 padding and unpadding routines (`pkcs7_pad`, `pkcs7_unpad`).
- Optional compiled C extension (`_native`) with seamless pure-Python fallback.
- Comprehensive test suite covering primitive types, nested structures, corruption resistance, and edge cases.
