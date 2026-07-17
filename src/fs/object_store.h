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

#ifndef _OBJECT_STORE_H_
#define _OBJECT_STORE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "file.h"

#define FILE_OBJECT_FORMAT_VERSION 1u
#define FILE_OBJECT_HEADER_SIZE 20u

typedef struct file_object {
    file_t *file;
    uint32_t payload_offset;
    uint32_t payload_size;
    uint32_t generation;
    uint16_t namespace_id;
    uint16_t object_type;
    bool legacy;
} file_object_t;

int file_object_open(file_t *file, uint16_t namespace_id, uint16_t object_type, bool allow_legacy, file_object_t *object);
int file_object_read_at(const file_object_t *object, uint32_t offset, uint8_t *data, size_t len);
int file_object_put(file_t *file, uint16_t namespace_id, uint16_t object_type, const uint8_t *data, uint32_t len);

#endif // _OBJECT_STORE_H_
