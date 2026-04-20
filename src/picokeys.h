/*
 * This file is part of the Pico Keys SDK distribution (https://github.com/polhenarejos/pico-keys-sdk).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef _PICOKEYS_H_
#define _PICOKEYS_H_

#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#if defined(PICO_RP2040) || defined(PICO_RP2350)
#define PICO_PLATFORM
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "file.h"
#include "debug.h"

#if !defined(MIN)
#if defined(_MSC_VER)
#define MIN(a,b) (((a)<(b))?(a):(b))
#else
#define MIN(a, b) \
    ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
       _a < _b ? _a : _b; })
#endif
#endif
#if !defined(MAX)
#if defined(_MSC_VER)
#define MAX(a,b) (((a)>(b))?(a):(b))
#else
#define MAX(a, b) \
    ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
       _a > _b ? _a : _b; })
#endif
#endif

extern int picokey_init(void);

extern void low_flash_init_core1(void);

static inline uint16_t make_uint16_be(uint8_t b1, uint8_t b2) {
    return (b1 << 8) | b2;
}
static inline uint16_t make_uint16_le(uint8_t b1, uint8_t b2) {
    return (b2 << 8) | b1;
}
static inline uint16_t get_uint16_be(const uint8_t *b) {
    return make_uint16_be(b[0], b[1]);
}
static inline uint16_t get_uint16_le(const uint8_t *b) {
    return make_uint16_le(b[0], b[1]);
}
static inline uint8_t put_uint16_be(uint16_t n, uint8_t *b) {
    *b++ = (n >> 8) & 0xff;
    *b = n & 0xff;
    return 2;
}
static inline uint8_t put_uint16_le(uint16_t n, uint8_t *b) {
    *b++ = n & 0xff;
    *b = (n >> 8) & 0xff;
    return 2;
}

static inline uint32_t make_uint32_be(uint8_t b1, uint8_t b2, uint8_t b3, uint8_t b4) {
    return (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;
}
static inline uint32_t make_uint32_le(uint8_t b1, uint8_t b2, uint8_t b3, uint8_t b4) {
    return (b4 << 24) | (b3 << 16) | (b2 << 8) | b1;
}
static inline uint32_t get_uint32_be(const uint8_t *b) {
    return make_uint32_be(b[0], b[1], b[2], b[3]);
}
static inline uint32_t get_uint32_le(const uint8_t *b) {
    return make_uint32_le(b[0], b[1], b[2], b[3]);
}
static inline uint32_t put_uint32_be(uint32_t n, uint8_t *b) {
    *b++ = (n >> 24) & 0xff;
    *b++ = (n >> 16) & 0xff;
    *b++ = (n >> 8) & 0xff;
    *b = n & 0xff;
    return 4;
}
static inline uint32_t put_uint32_le(uint32_t n, uint8_t *b) {
    *b++ = n & 0xff;
    *b++ = (n >> 8) & 0xff;
    *b++ = (n >> 16) & 0xff;
    *b = (n >> 24) & 0xff;
    return 4;
}

static inline uint64_t make_uint64_be(uint8_t b1, uint8_t b2, uint8_t b3, uint8_t b4, uint8_t b5, uint8_t b6, uint8_t b7, uint8_t b8) {
    return ((uint64_t) b1 << 56) | ((uint64_t) b2 << 48) | ((uint64_t) b3 << 40) | ((uint64_t) b4 << 32) | ((uint64_t) b5 << 24) | ((uint64_t) b6 << 16) | ((uint64_t) b7 << 8) | b8;
}
static inline uint64_t make_uint64_le(uint8_t b1, uint8_t b2, uint8_t b3, uint8_t b4, uint8_t b5, uint8_t b6, uint8_t b7, uint8_t b8) {
    return ((uint64_t) b8 << 56) | ((uint64_t) b7 << 48) | ((uint64_t) b6 << 40) | ((uint64_t) b5 << 32) | ((uint64_t) b4 << 24) | ((uint64_t) b3 << 16) | ((uint64_t) b2 << 8) | b1;
}
static inline uint64_t get_uint64_be(const uint8_t *b) {
    return make_uint64_be(b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
}
static inline uint64_t get_uint64_le(const uint8_t *b) {
    return make_uint64_le(b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
}
static inline uint32_t put_uint64_be(uint64_t n, uint8_t *b) {
    *b++ = (n >> 56) & 0xff;
    *b++ = (n >> 48) & 0xff;
    *b++ = (n >> 40) & 0xff;
    *b++ = (n >> 32) & 0xff;
    *b++ = (n >> 24) & 0xff;
    *b++ = (n >> 16) & 0xff;
    *b++ = (n >> 8) & 0xff;
    *b = n & 0xff;
    return 8;
}
static inline uint32_t put_uint64_le(uint64_t n, uint8_t *b) {
    *b++ = n & 0xff;
    *b++ = (n >> 8) & 0xff;
    *b++ = (n >> 16) & 0xff;
    *b++ = (n >> 24) & 0xff;
    *b++ = (n >> 32) & 0xff;
    *b++ = (n >> 40) & 0xff;
    *b++ = (n >> 48) & 0xff;
    *b = (n >> 56) & 0xff;
    return 8;
}

extern void low_flash_available(void);
extern int flash_clear_file(file_t *file);

extern int (*button_pressed_cb)(uint8_t);

extern bool is_req_button_pending(void);

#define PICOKEYS_OK                              0
#define PICOKEYS_ERR_NO_MEMORY                   -1000
#define PICOKEYS_ERR_MEMORY_FATAL                -1001
#define PICOKEYS_ERR_NULL_PARAM                  -1002
#define PICOKEYS_ERR_FILE_NOT_FOUND              -1003
#define PICOKEYS_ERR_BLOCKED                     -1004
#define PICOKEYS_NO_LOGIN                        -1005
#define PICOKEYS_EXEC_ERROR                      -1006
#define PICOKEYS_WRONG_LENGTH                    -1007
#define PICOKEYS_WRONG_DATA                      -1008
#define PICOKEYS_WRONG_DKEK                      -1009
#define PICOKEYS_WRONG_SIGNATURE                 -1010
#define PICOKEYS_WRONG_PADDING                   -1011
#define PICOKEYS_VERIFICATION_FAILED             -1012

#define PICOKEYS_CHECK(x) do { ret = (x); if (ret != PICOKEYS_OK) goto err; } while (0)

extern int set_atr(void);

#endif
