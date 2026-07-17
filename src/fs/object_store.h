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

#define FILE_OBJECT_FORMAT_VERSION 1u
#define FILE_OBJECT_HEADER_SIZE 20u
#define FILE_OBJECT_INVALID_HANDLE 0u
#define FILE_OBJECT_MAX_HANDLES 8u

typedef uint32_t file_object_handle_t;

typedef struct file_object_id {
    uint16_t namespace_id;
    uint16_t object_type;
    uint16_t fid;
} file_object_id_t;

typedef struct file_object_info {
    uint32_t payload_size;
    uint32_t generation;
} file_object_info_t;

int file_object_open(const file_object_id_t *object_id, file_object_handle_t *handle);
int file_object_get_info(file_object_handle_t handle, file_object_info_t *info);
int file_object_read_at(file_object_handle_t handle, uint32_t offset, uint8_t *data, size_t len);
int file_object_close(file_object_handle_t handle);
int file_object_put(const file_object_id_t *object_id, const uint8_t *data, uint32_t len);
int file_object_delete_no_commit(const file_object_id_t *object_id);
int file_object_delete(const file_object_id_t *object_id);

#endif // _OBJECT_STORE_H_
