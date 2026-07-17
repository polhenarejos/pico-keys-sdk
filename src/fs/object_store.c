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

#include "picokeys.h"
#include "object_store.h"

#define FILE_OBJECT_MAGIC_SIZE 4u
#define FILE_OBJECT_VERSION_OFFSET 4u
#define FILE_OBJECT_HEADER_SIZE_OFFSET 5u
#define FILE_OBJECT_NAMESPACE_OFFSET 6u
#define FILE_OBJECT_TYPE_OFFSET 8u
#define FILE_OBJECT_FID_OFFSET 10u
#define FILE_OBJECT_GENERATION_OFFSET 12u
#define FILE_OBJECT_PAYLOAD_SIZE_OFFSET 16u

static const uint8_t file_object_magic[FILE_OBJECT_MAGIC_SIZE] = { 'P', 'K', 'O', '1' };

int file_object_open(file_t *file, uint16_t namespace_id, uint16_t object_type, bool allow_legacy, file_object_t *object) {
    if (!file || !object || !file_has_data(file)) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }

    uint32_t file_size = file_get_size(file);
    uint8_t magic[FILE_OBJECT_MAGIC_SIZE];
    if (file_size < sizeof(magic)) {
        if (!allow_legacy) {
            return PICOKEYS_WRONG_DATA;
        }
        *object = (file_object_t) { .file = file, .payload_offset = 0, .payload_size = file_size, .generation = 0, .namespace_id = namespace_id, .object_type = object_type, .legacy = true };
        return PICOKEYS_OK;
    }
    if (file_read_at(file, 0, magic, sizeof(magic)) != PICOKEYS_OK) {
        return PICOKEYS_EXEC_ERROR;
    }
    if (memcmp(magic, file_object_magic, sizeof(magic)) != 0) {
        if (!allow_legacy) {
            return PICOKEYS_WRONG_DATA;
        }
        *object = (file_object_t) { .file = file, .payload_offset = 0, .payload_size = file_size, .generation = 0, .namespace_id = namespace_id, .object_type = object_type, .legacy = true };
        return PICOKEYS_OK;
    }
    if (file_size < FILE_OBJECT_HEADER_SIZE) {
        return PICOKEYS_WRONG_DATA;
    }

    uint8_t header[FILE_OBJECT_HEADER_SIZE];
    if (file_read_at(file, 0, header, sizeof(header)) != PICOKEYS_OK) {
        return PICOKEYS_EXEC_ERROR;
    }
    uint32_t payload_size = get_uint32_be(header + FILE_OBJECT_PAYLOAD_SIZE_OFFSET);
    uint32_t generation = get_uint32_be(header + FILE_OBJECT_GENERATION_OFFSET);
    if (header[FILE_OBJECT_VERSION_OFFSET] != FILE_OBJECT_FORMAT_VERSION || header[FILE_OBJECT_HEADER_SIZE_OFFSET] != FILE_OBJECT_HEADER_SIZE || get_uint16_be(header + FILE_OBJECT_NAMESPACE_OFFSET) != namespace_id || get_uint16_be(header + FILE_OBJECT_TYPE_OFFSET) != object_type || get_uint16_be(header + FILE_OBJECT_FID_OFFSET) != file->fid || generation == 0 || payload_size != file_size - FILE_OBJECT_HEADER_SIZE) {
        return PICOKEYS_WRONG_DATA;
    }

    *object = (file_object_t) { .file = file, .payload_offset = FILE_OBJECT_HEADER_SIZE, .payload_size = payload_size, .generation = generation, .namespace_id = namespace_id, .object_type = object_type, .legacy = false };
    return PICOKEYS_OK;
}

int file_object_read_at(const file_object_t *object, uint32_t offset, uint8_t *data, size_t len) {
    if (!object || !object->file || (!data && len > 0) || offset > object->payload_size || len > object->payload_size - offset) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    return file_read_at(object->file, object->payload_offset + offset, data, len);
}

int file_object_put(file_t *file, uint16_t namespace_id, uint16_t object_type, const uint8_t *data, uint32_t len) {
    if (!file || (!data && len > 0)) {
        return PICOKEYS_ERR_NULL_PARAM;
    }

    uint32_t generation = 1;
    if (file_has_data(file)) {
        file_object_t current;
        int r = file_object_open(file, namespace_id, object_type, false, &current);
        if (r != PICOKEYS_OK) {
            return r;
        }
        if (current.generation == UINT32_MAX) {
            return PICOKEYS_WRONG_DATA;
        }
        generation = current.generation + 1;
    }
    if (len > UINT32_MAX - FILE_OBJECT_HEADER_SIZE) {
        return PICOKEYS_ERR_NO_MEMORY;
    }

    uint32_t record_size = FILE_OBJECT_HEADER_SIZE + len;
    uint8_t *record = (uint8_t *)calloc(1, record_size);
    if (!record) {
        return PICOKEYS_ERR_MEMORY_FATAL;
    }
    memcpy(record, file_object_magic, sizeof(file_object_magic));
    record[FILE_OBJECT_VERSION_OFFSET] = FILE_OBJECT_FORMAT_VERSION;
    record[FILE_OBJECT_HEADER_SIZE_OFFSET] = FILE_OBJECT_HEADER_SIZE;
    put_uint16_be(namespace_id, record + FILE_OBJECT_NAMESPACE_OFFSET);
    put_uint16_be(object_type, record + FILE_OBJECT_TYPE_OFFSET);
    put_uint16_be(file->fid, record + FILE_OBJECT_FID_OFFSET);
    put_uint32_be(generation, record + FILE_OBJECT_GENERATION_OFFSET);
    put_uint32_be(len, record + FILE_OBJECT_PAYLOAD_SIZE_OFFSET);
    if (len > 0) {
        memcpy(record + FILE_OBJECT_HEADER_SIZE, data, len);
    }

    int r = file_put_data(file, record, record_size);
    memset(record, 0, record_size);
    free(record);
    return r;
}
