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

#ifndef _BYTE_ARRAY_H_
#define _BYTE_ARRAY_H_

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t *data;
    size_t len;
} byte_array_t;

typedef struct {
    uint8_t *data;
    size_t len;
    size_t capacity;
} byte_buffer_t;

typedef struct {
    const uint8_t *data;
    size_t len;
} const_byte_array_t;

#define BYTE_ARRAY(buffer_, length_) ((byte_array_t){ .data = (buffer_), .len = (length_) })
#define BYTE_BUFFER(buffer_, capacity_) ((byte_buffer_t){ .data = (buffer_), .len = 0, .capacity = (capacity_) })
#define CONST_BYTE_ARRAY(buffer_, length_) ((const_byte_array_t){ .data = (buffer_), .len = (length_) })

#endif
