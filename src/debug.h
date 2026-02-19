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

static inline void debug_payload_impl(const char *name, const uint8_t *p, size_t s, const char *file, int line) {
    printf("Payload %s (%zu bytes) [%s:%d]:\n", name, s, file, line);
    for (size_t i = 0; i < s; i += 16) {
        printf("%" PRIxPTR "h : ", (uintptr_t)(p + i));
        for (size_t j = 0; j < 16; j++) {
            if (j < s - i) {
                printf("%02X ", p[i + j]);
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
            if (j < s - i && p[i + j] > 32 && p[i + j] != 127 && p[i + j] < 176) {
                printf("%c", p[i + j]);
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

static inline void debug_data_impl(const char *name, const uint8_t *p, size_t s, const char *file, int line) {
    printf("Data %s (%zu bytes) [%s:%d]:\n", name, s, file, line);
    for (size_t i = 0; i < s; i++) {
        printf("%02X", p[i]);
    }
    printf("\n");
}

#define DEBUG_PAYLOAD(_p, _s) debug_payload_impl(#_p, (const uint8_t *)(_p), (size_t)(_s), __FILE__, __LINE__)
#define DEBUG_DATA(_p, _s) debug_data_impl(#_p, (const uint8_t *)(_p), (size_t)(_s), __FILE__, __LINE__)

#else
#define DEBUG_PAYLOAD(_p, _s)
#define DEBUG_DATA(_p, _s)
#endif

#endif // _DEBUG_H_
