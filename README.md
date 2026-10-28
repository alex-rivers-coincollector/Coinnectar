# Coinnectar

[![CI](https://github.com/coinnectar/coinnectar/actions/workflows/ci.yml/badge.svg)](https://github.com/coinnectar/coinnectar/actions)
[![PyPI version](https://img.shields.io/pypi/v/coinnectar.svg)](https://pypi.org/project/coinnectar/)
[![Python Versions](https://img.shields.io/pypi/pyversions/coinnectar.svg)](https://pypi.org/project/coinnectar/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A lightweight, robust Python + C library engineered for secure binary data serialization and cryptographic integrity primitives. Designed primarily for fintech infrastructure, inter-service messaging, and internal tooling where performance, memory safety, and tamper resistance are paramount.

---

## Highlights

- **Compact Binary Protocol:** Structured Tag-Length-Value (TLV) encoding with minimal overhead and built-in IEEE 802.3 CRC32 header verification.
- **Cryptographic Envelopes:** Tamper-evident message envelopes with built-in HMAC authentication, nonces, and timestamp expiration to protect against replay attacks.
- **Timing Attack Resilience:** Constant-time comparison primitives in ANSI C with seamless pure-Python fallbacks.
- **Zero Mandatory Dependencies:** Operates completely within Python standard library primitives when native build tools are unavailable.
- **Optional C Speedups:** Optional compiled C core (`_native`) providing accelerated CRC32, memory comparison, and XOR stream masking.
- **Type Safe & Tested:** Fully type-annotated (PEP 561 compliant) with 100% test coverage across core serialization paths.

---

## Installation

### Stable Release from PyPI

```bash
pip install coinnectar
```

### From Source

```bash
git clone https://github.com/coinnectar/coinnectar.git
cd coinnectar
pip install .
```

*Note: If a C compiler (GCC, Clang, or MSVC) is available, `setup.py` automatically compiles the `_native` C acceleration module. If no compiler is found, the installation cleanly defaults to the pure-Python implementation without error.*

---

## Quickstart

### 1. Binary Serialization

```python
import coinnectar

# Arbitrary nested data structure
transaction = {
    "tx_id": "tx_20251025_001",
    "sender_account": "ACC_44921",
    "amount_cents": 150000,
    "currency": "USD",
    "settled": True,
    "tags": ["settlement", "automated"],
}

# Serialize into compact wire bytes (includes magic header & CRC32 checksum)
wire_bytes = coinnectar.dumps(transaction)

# Deserialize back into Python objects with automatic integrity verification
decoded = coinnectar.loads(wire_bytes)
assert decoded["amount_cents"] == 150000
```

### 2. Authenticated Message Envelopes

```python
from coinnectar import pack_envelope, unpack_envelope, generate_key, IntegrityError

# 256-bit symmetric key
signing_key = generate_key(32)

payload = {
    "action": "CREDIT_ACCOUNT",
    "account": "ACC_8921",
    "amount": 250.00
}

# Sign and serialize envelope
packet = pack_envelope(
    data=payload,
    secret_key=signing_key,
    metadata={"source_service": "payments-worker-02"}
)

# Unpack and verify signature (with 30-second freshness window)
envelope = unpack_envelope(packet, secret_key=signing_key, max_age_seconds=30)
print(f"Verified message from {envelope.metadata['source_service']}: {envelope.data}")
```

### 3. Cryptographic Primitives & Encrypt-then-MAC

```python
from coinnectar import (
    constant_time_compare,
    derive_key,
    encrypt_then_mac,
    mac_then_decrypt,
    generate_key,
    xor_mask,
)

# Authenticated Encryption (Encrypt-then-MAC)
k_enc, k_mac = generate_key(32), generate_key(32)
ciphertext = encrypt_then_mac(b"Confidential transaction data", k_enc, k_mac)
decrypted = mac_then_decrypt(ciphertext, k_enc, k_mac)

# Side-channel safe token comparison
is_valid = constant_time_compare(b"user_provided_token", b"stored_secret_token")

# Subkey derivation using PBKDF2-HMAC-SHA256
derived_key = derive_key(
    secret=b"master_app_secret",
    salt=b"unique_tenant_salt_16b",
    length=32,
    iterations=100_000
)

# Wire stream masking
masked = xor_mask(b"sensitive wire bytes", key=b"transient_key")
```

---

## Wire Protocol Specification

Coinnectar packets utilize a 14-byte binary wire header followed by the TLV payload:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Magic (0x434E4354 "CNCT")                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |     Flags     |        CRC-32 Checksum        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       CRC-32 (cont.)          |         Payload Length        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Length (cont.)          |         Payload Data ...      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

---

## Project Structure

```
coinnectar/
├── README.md               # Project overview and quickstart
├── LICENSE                 # MIT License
├── pyproject.toml          # PEP 518/621 build specification & tool configs
├── setup.py                # Optional C extension build script
├── src/
│   └── coinnectar/
│       ├── __init__.py     # Public API surface
│       ├── core.py         # Exception hierarchy and Envelope definition
│       ├── serialize.py    # Binary serialization and wire parsing
│       ├── crypto.py       # HMAC, key derivation, and side-channel guards
│       └── utils.py        # Checksums, PKCS#7 padding, and validators
├── c_src/
│   ├── coinnectar.h        # C declarations and protocol constants
│   ├── serialize.c         # Fast CRC32, header validation, Python C-API
│   └── crypto_helpers.c    # Constant-time comparison & stream masking
├── tests/
│   ├── test_serialize.py   # Roundtrip, corruption, and boundary tests
│   ├── test_crypto.py      # HMAC, key derivation, and timing tests
│   └── test_utils.py       # CRC32, padding, and validator tests
├── docs/
│   └── usage.md            # Comprehensive developer manual
└── .gitignore              # Repository exclusion rules
```

---

## Maintainers & Governance

Coinnectar was initially created in 2020 and is actively maintained by **Elias Varga** and a small group of contributors.

We welcome issue reports, security suggestions, and pull requests. Please see our [Security Policy](https://github.com/coinnectar/coinnectar/security) for details on responsible vulnerability disclosure.

---

## License

Coinnectar is released under the [MIT License](LICENSE).
Copyright (c) 2020-2025 Elias Varga and Coinnectar Contributors.
