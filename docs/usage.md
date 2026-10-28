# Coinnectar Developer Guide

Welcome to the **Coinnectar** documentation. This guide explains how to integrate Coinnectar into your fintech services, data pipelines, and internal distributed tools.

---

## 1. Introduction & Design Goals

Coinnectar was designed to solve common challenges in internal financial infrastructure:
1. **Compact, Deterministic Binary Serialization:** Faster and more space-efficient than standard JSON for internal microservice RPC and event streams.
2. **Built-in Data Integrity:** Every serialized packet is protected with an IEEE 802.3 CRC32 header verification tag.
3. **Defense Against Side-Channels:** Timing-safe constant-time comparison primitives for authentication tokens and hashes.
4. **Zero-Dependency Core:** Functions seamlessly in pure Python with zero mandatory third-party dependencies, with optional C extensions for high-throughput environments.

---

## 2. Installation

### From PyPI
```bash
pip install coinnectar
```

### From Source with C Extensions
If a C compiler (GCC, Clang, or MSVC) is installed on your host, the build script automatically compiles the native C speedup routines:
```bash
git clone https://github.com/coinnectar/coinnectar.git
cd coinnectar
pip install .
```

### Pure Python Mode
To force pure Python mode (e.g. on PyPy or embedded environments without C toolchains):
```bash
export COINNECTAR_NO_C_EXTENSIONS=1
pip install .
```

---

## 3. Basic Serialization

Coinnectar provides familiar `dumps`, `loads`, `dump`, and `load` routines.

```python
import coinnectar

transaction = {
    "tx_id": "tx_9981249",
    "amount_cents": 250000,
    "currency": "EUR",
    "parties": {
        "sender": "usr_alpha",
        "recipient": "usr_beta"
    },
    "settled": True,
    "notes": None
}

# Serialize to binary bytes
binary_data = coinnectar.dumps(transaction)
print(f"Wire size: {len(binary_data)} bytes")

# Deserialize back into Python primitives
decoded = coinnectar.loads(binary_data)
assert decoded["tx_id"] == "tx_9981249"
```

### Streaming to and from Files
```python
import coinnectar

# Write to stream
with open("record.cnct", "wb") as f:
    coinnectar.dump(transaction, f)

# Read from stream
with open("record.cnct", "rb") as f:
    record = coinnectar.load(f)
```

---

## 4. Secure Envelopes & Authentication

In financial pipelines, data should rarely be transmitted without provenance and integrity verification. The `Envelope` class encapsulates payloads with unique nonces, timestamps, and HMAC-SHA256 signatures.

### Producing Signed Envelopes
```python
from coinnectar import pack_envelope, generate_key

# 32-byte shared secret key
shared_key = generate_key(32)

payload = {
    "action": "DEBIT_SETTLEMENT",
    "account": "ACC-5002",
    "amount": 10500.75
}

# Pack and sign in one step
wire_bytes = pack_envelope(
    data=payload,
    secret_key=shared_key,
    metadata={"service_source": "billing-core-01"}
)
```

### Verifying and Consuming Envelopes
On the receiving service, unpack and verify both the HMAC signature and maximum allowed age:

```python
from coinnectar import unpack_envelope, IntegrityError, SecurityError

try:
    # Unpack with a 60-second validity window
    envelope = unpack_envelope(
        wire_bytes,
        secret_key=shared_key,
        max_age_seconds=60
    )
    print("Received valid message:", envelope.data)
    print("Payload ID:", envelope.payload_id)
    print("Metadata:", envelope.metadata)

except IntegrityError:
    # Signature did not match or payload was altered in transit
    print("Security Alert: Signature mismatch! Payload rejected.")

except SecurityError as e:
    # Message was expired, replayed, or unsigned
    print(f"Security Alert: {e}")
```

---

## 5. Cryptographic Primitives

Coinnectar provides essential cryptographic building blocks:

### Constant-Time Comparison
Prevents side-channel timing attacks when validating external API tokens or hashes:
```python
from coinnectar import constant_time_compare

user_token = b"user_submitted_token_12345"
expected_token = b"database_stored_token_12345"

is_valid = constant_time_compare(user_token, expected_token)
```

### Subkey Derivation (PBKDF2)
Derive subkeys from master secrets and salts:
```python
from coinnectar import derive_key, generate_key

salt = generate_key(16)
derived_key = derive_key(
    secret=b"master_cluster_secret_phrase",
    salt=salt,
    length=32,
    iterations=100_000
)
```

### Wire Stream Masking
For lightweight obfuscation and transport-level frame masking:
```python
from coinnectar import xor_mask

data = b"Internal protocol frame"
mask_key = b"transient_stream_key"

masked = xor_mask(data, mask_key)
restored = xor_mask(masked, mask_key)
assert restored == data
```

---

## 6. Exception Hierarchy

All Coinnectar exceptions inherit from `CoinnectarError`:

```
CoinnectarError
 ├── SerializationError
 │    └── VersionMismatchError
 ├── IntegrityError
 └── SecurityError
```

- **`SerializationError`**: Raised when the wire format is corrupted, type tags are invalid, or recursion depth exceeds safety thresholds.
- **`VersionMismatchError`**: Raised when an incoming packet uses an unsupported protocol version.
- **`IntegrityError`**: Raised when the CRC32 checksum or HMAC authentication signature fails.
- **`SecurityError`**: Raised when a packet violates security constraints (e.g., expired timestamp, missing signature).

---

## 7. Best Practices in Production

1. **Always Set `max_age_seconds`:** When consuming messages from message queues (Kafka, RabbitMQ, SQS), enforce bounded expiration to protect against replay attacks.
2. **Rotate Shared Keys:** Use `derive_key` with unique tenant/session salts rather than a single static master key across all services.
3. **Tune Recursion Limits:** If parsing deeply nested tree structures, configure `Serializer(max_recursion_depth=...)` explicitly.
