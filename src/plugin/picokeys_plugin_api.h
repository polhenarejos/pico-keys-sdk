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

#ifndef PICOKEYS_PLUGIN_API_H
#define PICOKEYS_PLUGIN_API_H

#include <stddef.h>
#include <stdint.h>
#include "signal.h"

#if defined(_WIN32)
#define PICOKEYS_PLUGIN_EXPORT __declspec(dllexport)
#elif defined(__GNUC__) || defined(__clang__)
#define PICOKEYS_PLUGIN_EXPORT __attribute__((visibility("default")))
#else
#define PICOKEYS_PLUGIN_EXPORT
#endif

#if defined(ENABLE_EMULATION)
#if defined(__GNUC__) || defined(__clang__)
#define PICOKEYS_PLUGIN_HEADER_ATTR __attribute__((used))
#else
#define PICOKEYS_PLUGIN_HEADER_ATTR
#endif
#elif defined(__GNUC__) || defined(__clang__)
#define PICOKEYS_PLUGIN_HEADER_ATTR __attribute__((used, section(".plugin_header")))
#else
#define PICOKEYS_PLUGIN_HEADER_ATTR
#endif

#define PICOKEYS_PLUGIN_MAGIC 0x504b504cUL /* PKPL */
#define PICOKEYS_PLUGIN_ABI_VERSION 5u

#ifndef PICOKEYS_PLUGIN_FLASH_BASE
#define PICOKEYS_PLUGIN_FLASH_BASE 0x10112000UL
#endif

#ifndef PICOKEYS_PLUGIN_FLASH_SIZE
#define PICOKEYS_PLUGIN_FLASH_SIZE 0x000fa000UL
#endif

#ifndef PICOKEYS_PLUGIN_RAM_BASE
#define PICOKEYS_PLUGIN_RAM_BASE 0x2007c000UL
#endif

#ifndef PICOKEYS_PLUGIN_RAM_SIZE
#define PICOKEYS_PLUGIN_RAM_SIZE 0x00004000UL
#endif

typedef struct pk_plugin_sha256_context {
    uintptr_t opaque[64];
} pk_plugin_sha256_context_t;

typedef struct pk_plugin_imports {
    uint32_t abi_version;
    uint32_t struct_size;
    int (*printf)(const char *fmt, ...);
    int (*signal_add)(uint8_t code, signal_flag_t flags, signal_handler_t handler);
    void (*mbedtls_sha256_init)(pk_plugin_sha256_context_t *ctx);
    void (*mbedtls_sha256_free)(pk_plugin_sha256_context_t *ctx);
    int (*mbedtls_sha256_starts)(pk_plugin_sha256_context_t *ctx, int is224);
    int (*mbedtls_sha256_update)(pk_plugin_sha256_context_t *ctx, const unsigned char *input, size_t ilen);
    int (*mbedtls_sha256_finish)(pk_plugin_sha256_context_t *ctx, unsigned char *output);
    int (*mbedtls_sha256)(const unsigned char *input, size_t ilen, unsigned char output[32], int is224);
    int (*mbedtls_ct_memcmp)(const void *a, const void *b, size_t n);
    void *(*memcpy)(void *dst, const void *src, size_t len);
    void *(*memset)(void *dst, int value, size_t len);
    int (*flash_add_page)(void *page);
    void (*flash_commit)(void);
    uint8_t *(*flash_read)(uintptr_t addr);
    int (*has_set_rtc)(void);
    int64_t (*get_rtc_time)(void);
    void (*pin_derive_verifier)(const uint8_t *pin, size_t pin_len, uint8_t verifier[32]);
    uint8_t *(*get_res_apdu)(void);
    uint16_t (*get_res_apdu_size)(void);
    void (*set_res_apdu_size)(uint16_t size);
} pk_plugin_imports_t;

typedef void (*pk_plugin_init_fn)(pk_plugin_imports_t *imports);

typedef struct pk_plugin_header {
    uint32_t magic;
    uint32_t abi_version;
    uint32_t header_size;
    uint32_t image_size;
    uintptr_t data_load_start;
    uintptr_t data_start;
    uint32_t data_size;
    uintptr_t bss_start;
    uint32_t bss_size;
    pk_plugin_init_fn init;
} pk_plugin_header_t;

void plugin_init(void);

#endif
