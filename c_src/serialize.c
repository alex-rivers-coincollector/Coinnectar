/**
 * Coinnectar Fast Binary Serialization Primitives & C Module Init
 * 
 * Copyright (c) 2020-2025 Elias Varga and Coinnectar Contributors.
 * Distributed under the MIT License (see LICENSE for details).
 */

#include "coinnectar.h"

/* IEEE 802.3 standard CRC32 lookup table */
static uint32_t crc32_table[256];
static int crc32_table_initialized = 0;

static void init_crc32_table(void) {
    uint32_t polynomial = 0xEDB88320U;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) {
            if (c & 1) {
                c = polynomial ^ (c >> 1);
            } else {
                c = c >> 1;
            }
        }
        crc32_table[i] = c;
    }
    crc32_table_initialized = 1;
}

/**
 * Compute IEEE 802.3 CRC32 checksum over a byte buffer.
 */
uint32_t cn_crc32(const uint8_t *data, size_t length) {
    if (!crc32_table_initialized) {
        init_crc32_table();
    }

    uint32_t crc = 0xFFFFFFFFU;
    for (size_t i = 0; i < length; i++) {
        uint8_t index = (uint8_t)((crc ^ data[i]) & 0xFF);
        crc = crc32_table[index] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFU;
}

/**
 * Python wrapper: crc32(data: bytes) -> int
 */
PyObject* py_cn_crc32(PyObject *self, PyObject *args) {
    Py_buffer buf;

    if (!PyArg_ParseTuple(args, "y*", &buf)) {
        return NULL;
    }

    uint32_t checksum = cn_crc32((const uint8_t *)buf.buf, (size_t)buf.len);
    PyBuffer_Release(&buf);

    return PyLong_FromUnsignedLong(checksum);
}

/**
 * Validate and unpack raw wire header bytes.
 * Returns tuple: (version, flags, length, crc32)
 */
PyObject* py_cn_fast_validate_header(PyObject *self, PyObject *args) {
    Py_buffer buf;

    if (!PyArg_ParseTuple(args, "y*", &buf)) {
        return NULL;
    }

    if (buf.len < CN_HEADER_SIZE) {
        PyBuffer_Release(&buf);
        PyErr_SetString(PyExc_ValueError, "Header is smaller than minimum required header size");
        return NULL;
    }

    const uint8_t *ptr = (const uint8_t *)buf.buf;

    /* Check magic 0x434E4354 ("CNCT") */
    uint32_t magic = ((uint32_t)ptr[0] << 24) |
                     ((uint32_t)ptr[1] << 16) |
                     ((uint32_t)ptr[2] << 8)  |
                     ((uint32_t)ptr[3]);

    if (magic != CN_MAGIC_U32) {
        PyBuffer_Release(&buf);
        PyErr_SetString(PyExc_ValueError, "Invalid Coinnectar magic signature");
        return NULL;
    }

    uint8_t version = ptr[4];
    uint8_t flags   = ptr[5];

    if (version != CN_PROTOCOL_VERSION) {
        PyBuffer_Release(&buf);
        PyErr_SetString(PyExc_ValueError, "Unsupported protocol version");
        return NULL;
    }

    uint32_t crc = ((uint32_t)ptr[6]  << 24) |
                   ((uint32_t)ptr[7]  << 16) |
                   ((uint32_t)ptr[8]  << 8)  |
                   ((uint32_t)ptr[9]);

    uint32_t length = ((uint32_t)ptr[10] << 24) |
                      ((uint32_t)ptr[11] << 16) |
                      ((uint32_t)ptr[12] << 8)  |
                      ((uint32_t)ptr[13]);

    if (length > CN_MAX_PAYLOAD_SIZE) {
        PyBuffer_Release(&buf);
        PyErr_SetString(PyExc_ValueError, "Payload exceeds maximum allowed size (64MB)");
        return NULL;
    }

    /* Verify overall buffer has enough bytes for payload */
    if ((size_t)buf.len < (CN_HEADER_SIZE + (size_t)length)) {
        PyBuffer_Release(&buf);
        PyErr_SetString(PyExc_ValueError, "Incomplete packet: buffer is shorter than advertised payload");
        return NULL;
    }

    /* Validate payload checksum */
    uint32_t calc_crc = cn_crc32(ptr + CN_HEADER_SIZE, (size_t)length);
    if (calc_crc != crc) {
        PyBuffer_Release(&buf);
        PyErr_SetString(PyExc_ValueError, "Checksum verification failed: corrupt payload");
        return NULL;
    }

    PyBuffer_Release(&buf);

    return Py_BuildValue("(BBIk)", version, flags, crc, length);
}

/* Method Table */
static PyMethodDef CoinnectarNativeMethods[] = {
    {
        "crc32",
        py_cn_crc32,
        METH_VARARGS,
        "Compute IEEE 802.3 CRC32 checksum for a bytes-like object."
    },
    {
        "constant_time_compare",
        py_cn_constant_time_compare,
        METH_VARARGS,
        "Compare two byte strings in constant time to prevent timing attacks."
    },
    {
        "xor_mask",
        py_cn_xor_mask,
        METH_VARARGS,
        "Apply symmetric stream masking to bytes using a secret key."
    },
    {
        "fast_validate_header",
        py_cn_fast_validate_header,
        METH_VARARGS,
        "Validate header magic, checksum, and payload bounds."
    },
    {NULL, NULL, 0, NULL}
};

/* Module Definition */
static struct PyModuleDef coinnectar_native_module = {
    PyModuleDef_HEAD_INIT,
    "_native",
    "Coinnectar C speedups and cryptographic helper routines.",
    -1,
    CoinnectarNativeMethods
};

/* Module Entry Point */
PyMODINIT_FUNC PyInit__native(void) {
    init_crc32_table();

    PyObject *m = PyModule_Create(&coinnectar_native_module);
    if (m == NULL) {
        return NULL;
    }

    /* Add module constants */
    if (PyModule_AddIntConstant(m, "PROTOCOL_VERSION", CN_PROTOCOL_VERSION) < 0) {
        Py_DECREF(m);
        return NULL;
    }
    if (PyModule_AddIntConstant(m, "HEADER_SIZE", CN_HEADER_SIZE) < 0) {
        Py_DECREF(m);
        return NULL;
    }
    if (PyModule_AddIntConstant(m, "MAX_PAYLOAD_SIZE", CN_MAX_PAYLOAD_SIZE) < 0) {
        Py_DECREF(m);
        return NULL;
    }

    return m;
}
