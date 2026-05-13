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

#ifndef _BOARD_H_
#define _BOARD_H_

#include <stdint.h>
#ifdef _MSC_VER
#include <windows.h>
struct timezone;
extern int gettimeofday(struct timeval *tp, struct timezone *tzp);
#else
#include <sys/time.h>
#endif

static inline uint32_t board_millis(void) {
    struct timeval start;
    gettimeofday(&start, NULL);
    uint64_t ms = (uint64_t)start.tv_sec * 1000ULL + (uint64_t)start.tv_usec / 1000ULL;
    return (uint32_t)ms;
}

#endif // _BOARD_H_
