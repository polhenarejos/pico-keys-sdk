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

typedef struct file_object_record {
    uint32_t payload_offset;
    uint32_t payload_size;
    uint32_t generation;
} file_object_record_t;

typedef struct file_object_handle_entry {
    file_object_id_t object_id;
    uint32_t generation;
    uint32_t payload_size;
    file_object_handle_t token;
} file_object_handle_entry_t;

static file_object_handle_entry_t file_object_handles[FILE_OBJECT_MAX_HANDLES];
static file_object_handle_t file_object_next_handle = 1u;

static bool file_object_id_valid(const file_object_id_t *object_id) {
    return object_id && object_id->fid != 0 && object_id->fid != UINT16_MAX;
}

static int file_object_parse(file_t *file, const file_object_id_t *object_id, file_object_record_t *record) {
    if (!file || !file_object_id_valid(object_id) || !record || !file_has_data(file)) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }

    uint32_t file_size = file_get_size(file);
    if (file_size < FILE_OBJECT_HEADER_SIZE) {
        return PICOKEYS_WRONG_DATA;
    }

    uint8_t header[FILE_OBJECT_HEADER_SIZE];
    if (file_read_at(file, 0, header, sizeof(header)) != PICOKEYS_OK) {
        return PICOKEYS_EXEC_ERROR;
    }
    uint32_t payload_size = get_uint32_be(header + FILE_OBJECT_PAYLOAD_SIZE_OFFSET);
    uint32_t generation = get_uint32_be(header + FILE_OBJECT_GENERATION_OFFSET);
    if (memcmp(header, file_object_magic, sizeof(file_object_magic)) != 0 || header[FILE_OBJECT_VERSION_OFFSET] != FILE_OBJECT_FORMAT_VERSION || header[FILE_OBJECT_HEADER_SIZE_OFFSET] != FILE_OBJECT_HEADER_SIZE || get_uint16_be(header + FILE_OBJECT_NAMESPACE_OFFSET) != object_id->namespace_id || get_uint16_be(header + FILE_OBJECT_TYPE_OFFSET) != object_id->object_type || get_uint16_be(header + FILE_OBJECT_FID_OFFSET) != object_id->fid || file->fid != object_id->fid || generation == 0 || payload_size != file_size - FILE_OBJECT_HEADER_SIZE) {
        return PICOKEYS_WRONG_DATA;
    }

    *record = (file_object_record_t) {
        .payload_offset = FILE_OBJECT_HEADER_SIZE,
        .payload_size = payload_size,
        .generation = generation
    };
    return PICOKEYS_OK;
}

static file_object_handle_entry_t *file_object_find_handle(file_object_handle_t handle) {
    if (handle == FILE_OBJECT_INVALID_HANDLE) {
        return NULL;
    }
    for (size_t i = 0; i < FILE_OBJECT_MAX_HANDLES; i++) {
        if (file_object_handles[i].token == handle) {
            return &file_object_handles[i];
        }
    }
    return NULL;
}

static bool file_object_handle_in_use(file_object_handle_t handle) {
    return file_object_find_handle(handle) != NULL;
}

static file_object_handle_t file_object_allocate_token(void) {
    do {
        file_object_handle_t handle = file_object_next_handle++;
        if (handle != FILE_OBJECT_INVALID_HANDLE && !file_object_handle_in_use(handle)) {
            return handle;
        }
    } while (true);
}

static int file_object_resolve(file_object_handle_t handle, file_t **file, file_object_record_t *record) {
    file_object_handle_entry_t *current = file_object_find_handle(handle);
    if (!current) {
        return PICOKEYS_ERR_STALE_HANDLE;
    }

    file_t *current_file = file_search(current->object_id.fid);
    int r = file_object_parse(current_file, &current->object_id, record);
    if (r == PICOKEYS_ERR_FILE_NOT_FOUND || r == PICOKEYS_WRONG_DATA) {
        return PICOKEYS_ERR_STALE_HANDLE;
    }
    if (r != PICOKEYS_OK) {
        return r;
    }
    if (record->generation != current->generation || record->payload_size != current->payload_size) {
        return PICOKEYS_ERR_STALE_HANDLE;
    }

    if (file) {
        *file = current_file;
    }
    return PICOKEYS_OK;
}

int file_object_open(const file_object_id_t *object_id, file_object_handle_t *handle) {
    if (!file_object_id_valid(object_id) || !handle) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    *handle = FILE_OBJECT_INVALID_HANDLE;

    file_object_record_t record;
    int r = file_object_parse(file_search(object_id->fid), object_id, &record);
    if (r != PICOKEYS_OK) {
        return r;
    }

    for (size_t i = 0; i < FILE_OBJECT_MAX_HANDLES; i++) {
        if (file_object_handles[i].token == FILE_OBJECT_INVALID_HANDLE) {
            file_object_handles[i] = (file_object_handle_entry_t) {
                .object_id = *object_id,
                .generation = record.generation,
                .payload_size = record.payload_size,
                .token = file_object_allocate_token()
            };
            *handle = file_object_handles[i].token;
            return PICOKEYS_OK;
        }
    }
    return PICOKEYS_ERR_NO_MEMORY;
}

int file_object_get_info(file_object_handle_t handle, file_object_info_t *info) {
    if (!info) {
        return PICOKEYS_ERR_NULL_PARAM;
    }

    file_object_record_t record;
    int r = file_object_resolve(handle, NULL, &record);
    if (r != PICOKEYS_OK) {
        return r;
    }
    *info = (file_object_info_t) {
        .payload_size = record.payload_size,
        .generation = record.generation
    };
    return PICOKEYS_OK;
}

int file_object_read_at(file_object_handle_t handle, uint32_t offset, uint8_t *data, size_t len) {
    if (!data && len > 0) {
        return PICOKEYS_ERR_NULL_PARAM;
    }

    file_t *file = NULL;
    file_object_record_t record;
    int r = file_object_resolve(handle, &file, &record);
    if (r != PICOKEYS_OK) {
        return r;
    }
    if (offset > record.payload_size || len > record.payload_size - offset) {
        return PICOKEYS_WRONG_LENGTH;
    }
    return file_read_at(file, record.payload_offset + offset, data, len);
}

int file_object_close(file_object_handle_t handle) {
    file_object_handle_entry_t *entry = file_object_find_handle(handle);
    if (!entry) {
        return PICOKEYS_ERR_STALE_HANDLE;
    }
    memset(entry, 0, sizeof(*entry));
    return PICOKEYS_OK;
}

int file_object_put(const file_object_id_t *object_id, const uint8_t *data, uint32_t len) {
    if (!file_object_id_valid(object_id) || (!data && len > 0)) {
        return PICOKEYS_ERR_NULL_PARAM;
    }

    file_t *file = file_search(object_id->fid);
    uint32_t generation = 1;
    if (file_has_data(file)) {
        file_object_record_t current;
        int r = file_object_parse(file, object_id, &current);
        if (r != PICOKEYS_OK) {
            return r;
        }
        if (current.generation == UINT32_MAX) {
            return PICOKEYS_WRONG_DATA;
        }
        generation = current.generation + 1;
    }
    else if (!file) {
        file = file_new(object_id->fid);
        if (!file) {
            return PICOKEYS_ERR_NO_MEMORY;
        }
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
    put_uint16_be(object_id->namespace_id, record + FILE_OBJECT_NAMESPACE_OFFSET);
    put_uint16_be(object_id->object_type, record + FILE_OBJECT_TYPE_OFFSET);
    put_uint16_be(object_id->fid, record + FILE_OBJECT_FID_OFFSET);
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

static int file_object_delete_internal(const file_object_id_t *object_id, bool commit) {
    if (!file_object_id_valid(object_id)) {
        return PICOKEYS_ERR_NULL_PARAM;
    }

    file_t *file = file_search(object_id->fid);
    file_object_record_t record;
    int r = file_object_parse(file, object_id, &record);
    if (r != PICOKEYS_OK) {
        return r;
    }
    return commit ? file_delete(file) : file_delete_no_commit(file);
}

int file_object_delete_no_commit(const file_object_id_t *object_id) {
    return file_object_delete_internal(object_id, false);
}

int file_object_delete(const file_object_id_t *object_id) {
    return file_object_delete_internal(object_id, true);
}
