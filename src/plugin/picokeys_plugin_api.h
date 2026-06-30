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
#define PICOKEYS_PLUGIN_ABI_VERSION 1u

#ifndef PICOKEYS_PLUGIN_FLASH_BASE
#define PICOKEYS_PLUGIN_FLASH_BASE 0x10112000UL
#endif

#ifndef PICOKEYS_PLUGIN_FLASH_SIZE
#define PICOKEYS_PLUGIN_FLASH_SIZE 0x000fa000UL
#endif

typedef struct pk_plugin_imports {
    uint32_t abi_version;
    uint32_t struct_size;
    int (*printf)(const char *fmt, ...);
    int (*signal_add)(uint8_t code, signal_flag_t flags, signal_handler_t handler);
} pk_plugin_imports_t;

typedef void (*pk_plugin_init_fn)(const pk_plugin_imports_t *imports);

typedef struct pk_plugin_header {
    uint32_t magic;
    uint32_t abi_version;
    uint32_t header_size;
    uint32_t image_size;
    pk_plugin_init_fn init;
} pk_plugin_header_t;

void plugin_init(void);

#endif
