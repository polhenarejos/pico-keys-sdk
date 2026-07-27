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

#ifndef _DEBUG_H_
#define _DEBUG_H_

#if defined(DEBUG_APDU) && DEBUG_APDU == 1
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "byte_array.h"

static inline void debug_payload_impl(const char *name, const_byte_array_t data, const char *file, int line) {
    printf("Payload %s (%zu bytes) [%s:%d]:\n", name, data.len, file, line);
    for (size_t i = 0; i < data.len; i += 16) {
        printf("%" PRIxPTR "h : ", (uintptr_t)(data.data + i));
        for (size_t j = 0; j < 16; j++) {
            if (j < data.len - i) {
                printf("%02X ", data.data[i + j]);
            }
            else {
                printf("   ");
            }
            if (j == 7) {
                printf(" ");
            }
        }
        printf(":  ");
        for (size_t j = 0; j < 16; j++) {
            if (j < data.len - i && data.data[i + j] > 32 && data.data[i + j] != 127 && data.data[i + j] < 176) {
                printf("%c", data.data[i + j]);
            }
            else {
                printf(" ");
            }
            if (j == 7) {
                printf(" ");
            }
        }
        printf("\n");
    }
    printf("\n");
}

static inline void debug_data_impl(const char *name, const_byte_array_t data, const char *file, int line) {
    printf("Data %s (%zu bytes) [%s:%d]:\n", name, data.len, file, line);
    for (size_t i = 0; i < data.len; i++) {
        printf("%02X", data.data[i]);
    }
    printf("\n");
}

#define DEBUG_PAYLOAD(_p, _s) debug_payload_impl(#_p, CONST_BYTE_ARRAY((const uint8_t *)(_p), (size_t)(_s)), __FILE__, __LINE__)
#define DEBUG_DATA(_p, _s) debug_data_impl(#_p, CONST_BYTE_ARRAY((const uint8_t *)(_p), (size_t)(_s)), __FILE__, __LINE__)

#else
#define DEBUG_PAYLOAD(_p, _s)
#define DEBUG_DATA(_p, _s)
#endif

#endif // _DEBUG_H_
