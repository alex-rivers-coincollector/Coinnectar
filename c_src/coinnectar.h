/**
 * Coinnectar C Core Extensions
 * 
 * Copyright (c) 2020-2025 Elias Varga and Coinnectar Contributors.
 * Distributed under the MIT License (see LICENSE for details).
 * 
 * High-performance serialization primitives and cryptographic utilities.
 */

#ifndef COINNECTAR_H
#define COINNECTAR_H

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Protocol Constants */
#define CN_MAGIC_U32            0x434E4354U /* ASCII "CNCT" */
#define CN_PROTOCOL_VERSION_V1  0x01
#define CN_PROTOCOL_VERSION_V2  0x02
#define CN_PROTOCOL_VERSION     CN_PROTOCOL_VERSION_V1
#define CN_HEADER_SIZE          14
#define CN_MAX_PAYLOAD_SIZE     (64 * 1024 * 1024) /* 64 MB security limit */
#define CN_MAX_RECURSION_DEPTH  128

/* Protocol Wire Flags */
#define CN_FLAG_NONE            0x00
#define CN_FLAG_COMPRESSED      0x01
#define CN_FLAG_AUTHENTICATED   0x02

/* Serialization Type Tags */
#define CN_TYPE_NULL            0x00
#define CN_TYPE_BOOL_FALSE      0x01
#define CN_TYPE_BOOL_TRUE       0x02
#define CN_TYPE_INT64           0x03
#define CN_TYPE_FLOAT64         0x04
#define CN_TYPE_BYTES           0x05
#define CN_TYPE_STRING          0x06
#define CN_TYPE_LIST            0x07
#define CN_TYPE_DICT            0x08

/* Error Return Codes */
#define CN_SUCCESS              0
#define CN_ERR_INVALID_MAGIC   -1
#define CN_ERR_VERSION_MISMATCH -2
#define CN_ERR_CORRUPT_DATA    -3
#define CN_ERR_OVERFLOW        -4
#define CN_ERR_CHECKSUM_FAILED -5
#define CN_ERR_UNSUPPORTED_TYPE -6
#define CN_ERR_NOMEM           -7
#define CN_ERR_MAX_DEPTH       -8

/* Wire Header Struct (Packed) */
#pragma pack(push, 1)
typedef struct {
    uint32_t magic;         /* Big-endian 0x434E4354 ("CNCT") */
    uint8_t  version;       /* Protocol version (e.g. 0x01) */
    uint8_t  flags;         /* Header flags (e.g. compression, encryption) */
    uint32_t crc32;         /* IEEE 802.3 CRC-32 checksum of payload */
    uint32_t length;        /* Payload length in bytes */
} cn_header_t;
#pragma pack(pop)

/* Core C Utility Prototypes */
uint32_t cn_crc32(const uint8_t *data, size_t length);
int cn_constant_time_memcmp(const uint8_t *a, const uint8_t *b, size_t length);
void cn_xor_mask(uint8_t *dest, const uint8_t *src, size_t len, const uint8_t *key, size_t key_len);

/* Python C-API Function Declarations */
PyObject* py_cn_crc32(PyObject *self, PyObject *args);
PyObject* py_cn_constant_time_compare(PyObject *self, PyObject *args);
PyObject* py_cn_xor_mask(PyObject *self, PyObject *args);
PyObject* py_cn_fast_validate_header(PyObject *self, PyObject *args);

#ifdef __cplusplus
}
#endif

#endif /* COINNECTAR_H */
