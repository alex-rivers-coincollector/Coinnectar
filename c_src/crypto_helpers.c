/**
 * Coinnectar Cryptographic Helpers & Constant-time Primitives
 * 
 * Copyright (c) 2020-2025 Elias Varga and Coinnectar Contributors.
 * Distributed under the MIT License (see LICENSE for details).
 */

#include "coinnectar.h"

/**
 * Perform constant-time memory comparison between two buffers.
 * 
 * Prevents side-channel timing attacks when validating cryptographic hashes,
 * HMAC digests, and secret tokens in fintech transaction pipelines.
 * 
 * @param a First byte buffer
 * @param b Second byte buffer
 * @param length Number of bytes to compare
 * @return 0 if buffers are identical, non-zero (-1) otherwise.
 */
int cn_constant_time_memcmp(const uint8_t *a, const uint8_t *b, size_t length) {
    uint8_t accumulator = 0;
    for (size_t i = 0; i < length; i++) {
        accumulator |= (a[i] ^ b[i]);
    }
    return (accumulator == 0) ? 0 : -1;
}

/**
 * Apply symmetric XOR stream masking over data using a repeating key.
 * 
 * Used for fast lightweight wire-transport obfuscation and frame masking.
 * 
 * @param dest Destination buffer (must have at least len bytes allocated)
 * @param src Source buffer
 * @param len Number of bytes to mask
 * @param key Masking key
 * @param key_len Length of key in bytes
 */
void cn_xor_mask(uint8_t *dest, const uint8_t *src, size_t len, const uint8_t *key, size_t key_len) {
    if (key_len == 0 || dest == NULL || src == NULL) {
        if (dest != NULL && src != NULL && dest != src) {
            memcpy(dest, src, len);
        }
        return;
    }

    for (size_t i = 0; i < len; i++) {
        dest[i] = src[i] ^ key[i % key_len];
    }
}

/**
 * Python wrapper: constant_time_compare(val1: bytes, val2: bytes) -> bool
 */
PyObject* py_cn_constant_time_compare(PyObject *self, PyObject *args) {
    Py_buffer buf_a, buf_b;

    if (!PyArg_ParseTuple(args, "y*y*", &buf_a, &buf_b)) {
        return NULL;
    }

    if (buf_a.len != buf_b.len) {
        PyBuffer_Release(&buf_a);
        PyBuffer_Release(&buf_b);
        Py_RETURN_FALSE;
    }

    int result = cn_constant_time_memcmp(
        (const uint8_t *)buf_a.buf,
        (const uint8_t *)buf_b.buf,
        (size_t)buf_a.len
    );

    PyBuffer_Release(&buf_a);
    PyBuffer_Release(&buf_b);

    if (result == 0) {
        Py_RETURN_TRUE;
    } else {
        Py_RETURN_FALSE;
    }
}

/**
 * Python wrapper: xor_mask(data: bytes, key: bytes) -> bytes
 */
PyObject* py_cn_xor_mask(PyObject *self, PyObject *args) {
    Py_buffer data_buf, key_buf;

    if (!PyArg_ParseTuple(args, "y*y*", &data_buf, &key_buf)) {
        return NULL;
    }

    if (key_buf.len == 0) {
        PyErr_SetString(PyExc_ValueError, "Mask key must not be empty");
        PyBuffer_Release(&data_buf);
        PyBuffer_Release(&key_buf);
        return NULL;
    }

    PyObject *result_bytes = PyBytes_FromStringAndSize(NULL, data_buf.len);
    if (!result_bytes) {
        PyBuffer_Release(&data_buf);
        PyBuffer_Release(&key_buf);
        return PyErr_NoMemory();
    }

    uint8_t *dest = (uint8_t *)PyBytes_AS_STRING(result_bytes);
    cn_xor_mask(
        dest,
        (const uint8_t *)data_buf.buf,
        (size_t)data_buf.len,
        (const uint8_t *)key_buf.buf,
        (size_t)key_buf.len
    );

    PyBuffer_Release(&data_buf);
    PyBuffer_Release(&key_buf);

    return result_bytes;
}
