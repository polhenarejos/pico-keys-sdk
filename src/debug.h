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
#define DEBUG_PAYLOAD(_p, _s) { \
        printf("Payload %s (%zu bytes) [%s:%d]:\n", #_p, (size_t)(_s), __FILE__, __LINE__); \
        for (size_t _i = 0; _i < (size_t)(_s); _i += 16) { \
            printf("%" PRIxPTR "h : ", (uintptr_t) (_i + _p)); \
            for (size_t _j = 0; _j < 16; _j++) { \
                if (_j < (size_t)(_s) - _i) printf("%02X ", (_p)[_i + _j]); \
                else printf("   "); \
                if (_j == 7) printf(" "); \
            } printf(":  "); \
            for (size_t _j = 0; _j < 16; _j++) { \
                if (_j < (size_t)(_s) - _i && (_p)[_i + _j] > 32 && (_p)[_i + _j] != 127 && (_p)[_i + _j] < 176) printf("%c", (_p)[_i + _j]); \
                else printf(" "); \
                if (_j == 7) printf(" "); \
            } \
            printf("\n"); \
        } printf("\n"); \
}
#define DEBUG_DATA(_p, _s) {                                                    \
        printf("Data %s (%zu bytes) [%s:%d]:\n", #_p, (size_t)(_s), __FILE__, __LINE__);      \
        char *_tmp = (char *) calloc(2 * (_s) + 1, sizeof(char)); \
        for (size_t _i = 0; _i < (size_t)(_s); _i++) {    \
            sprintf(&_tmp[2 * _i], "%02X", (_p)[_i]);       \
        }                                                \
        printf("%s\n", _tmp);                             \
        free(_tmp);                                       \
    }

#else
#define DEBUG_PAYLOAD(_p, _s)
#define DEBUG_DATA(_p, _s)
#endif

#endif // _DEBUG_H_
