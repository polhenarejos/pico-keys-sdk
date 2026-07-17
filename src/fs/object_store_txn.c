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

#define FILE_OBJECT_TXN_FORMAT_VERSION 1u
#define FILE_OBJECT_TXN_RECORD_HEADER_SIZE 32u
#define FILE_OBJECT_TXN_COMMIT_HEADER_SIZE 48u
#define FILE_OBJECT_TXN_COMMIT_SIZE (FILE_OBJECT_TXN_COMMIT_HEADER_SIZE + FILE_OBJECT_AUTH_TAG_SIZE)
#define FILE_OBJECT_TXN_COMMIT_MARKER 0x7fu
#define FILE_OBJECT_TXN_FLAG_DELETED 0x01u
#define FILE_OBJECT_TXN_READ_CHUNK_SIZE 256u
#define FILE_OBJECT_TXN_COMMIT_TIMEOUT_MS 5000u

#define FILE_OBJECT_TXN_VERSION_OFFSET 4u
#define FILE_OBJECT_TXN_HEADER_SIZE_OFFSET 5u
#define FILE_OBJECT_TXN_SLOT_OFFSET 6u
#define FILE_OBJECT_TXN_RECORD_RESERVED_OFFSET 7u
#define FILE_OBJECT_TXN_NAMESPACE_OFFSET 8u
#define FILE_OBJECT_TXN_TYPE_OFFSET 10u
#define FILE_OBJECT_TXN_OBJECT_ID_OFFSET 12u
#define FILE_OBJECT_TXN_GENERATION_OFFSET 16u
#define FILE_OBJECT_TXN_RECORD_ID_OFFSET 20u
#define FILE_OBJECT_TXN_PAYLOAD_SIZE_OFFSET 24u
#define FILE_OBJECT_TXN_RECORD_FID_OFFSET 28u
#define FILE_OBJECT_TXN_RECORD_RESERVED_2_OFFSET 30u

#define FILE_OBJECT_TXN_COMMIT_MARKER_OFFSET 7u
#define FILE_OBJECT_TXN_COMMIT_RECORD_FID_OFFSET 24u
#define FILE_OBJECT_TXN_COMMIT_RECORD_SLOT_OFFSET 26u
#define FILE_OBJECT_TXN_COMMIT_FLAGS_OFFSET 27u
#define FILE_OBJECT_TXN_COMMIT_PAYLOAD_SIZE_OFFSET 28u
#define FILE_OBJECT_TXN_COMMIT_RECORD_TAG_OFFSET 32u
#define FILE_OBJECT_TXN_COMMIT_TAG_OFFSET 48u

static const uint8_t file_object_txn_record_magic[4] = { 'P', 'K', 'R', '2' };
static const uint8_t file_object_txn_commit_magic[4] = { 'P', 'K', 'C', '2' };

typedef struct file_object_txn_state {
    uint32_t generation;
    uint32_t record_id;
    uint32_t payload_size;
    uint8_t commit_slot;
    uint8_t record_slot;
    bool deleted;
} file_object_txn_state_t;

typedef struct file_object_txn_handle_entry {
    file_object_txn_layout_t layout;
    file_object_txn_state_t state;
    file_object_txn_handle_t token;
} file_object_txn_handle_entry_t;

static file_object_txn_handle_entry_t file_object_txn_handles[FILE_OBJECT_TXN_MAX_HANDLES];
static file_object_txn_handle_t file_object_txn_next_handle = 1u;

static bool file_object_txn_auth_valid(const file_object_authenticator_t *auth) {
    return auth && auth->start && auth->update && auth->finish;
}

static bool file_object_txn_layout_valid(const file_object_txn_layout_t *layout) {
    if (!layout) {
        return false;
    }

    const uint16_t fids[4] = { layout->record_fid[0], layout->record_fid[1], layout->commit_fid[0], layout->commit_fid[1] };
    for (size_t i = 0; i < sizeof(fids) / sizeof(fids[0]); i++) {
        if (fids[i] == 0 || fids[i] == UINT16_MAX || file_search_by_fid(fids[i], NULL, SPECIFY_ANY)) {
            return false;
        }
        for (size_t j = 0; j < i; j++) {
            if (fids[i] == fids[j]) {
                return false;
            }
        }
    }
    return true;
}

static bool file_object_txn_tag_equal(const uint8_t *left, const uint8_t *right) {
    uint8_t difference = 0;
    for (size_t i = 0; i < FILE_OBJECT_AUTH_TAG_SIZE; i++) {
        difference |= left[i] ^ right[i];
    }
    return difference == 0;
}

static void file_object_txn_auth_abort(const file_object_authenticator_t *auth) {
    if (auth && auth->abort) {
        auth->abort(auth->ctx);
    }
}

static int file_object_txn_auth_buffer(const file_object_authenticator_t *auth, const uint8_t *first, size_t first_len, const uint8_t *second, size_t second_len, uint8_t tag[FILE_OBJECT_AUTH_TAG_SIZE]) {
    int r = auth->start(auth->ctx);
    if (r != PICOKEYS_OK) {
        file_object_txn_auth_abort(auth);
        return r;
    }
    r = auth->update(auth->ctx, first, first_len);
    if (r == PICOKEYS_OK && second_len > 0) {
        r = auth->update(auth->ctx, second, second_len);
    }
    if (r == PICOKEYS_OK) {
        r = auth->finish(auth->ctx, tag);
    }
    if (r != PICOKEYS_OK) {
        file_object_txn_auth_abort(auth);
    }
    return r;
}

static int file_object_txn_auth_record(const file_object_authenticator_t *auth, const file_t *file, const uint8_t header[FILE_OBJECT_TXN_RECORD_HEADER_SIZE], uint32_t payload_size, uint8_t tag[FILE_OBJECT_AUTH_TAG_SIZE]) {
    int r = auth->start(auth->ctx);
    if (r != PICOKEYS_OK) {
        file_object_txn_auth_abort(auth);
        return r;
    }
    r = auth->update(auth->ctx, header, FILE_OBJECT_TXN_RECORD_HEADER_SIZE);

    uint8_t buffer[FILE_OBJECT_TXN_READ_CHUNK_SIZE];
    uint32_t offset = 0;
    while (r == PICOKEYS_OK && offset < payload_size) {
        size_t chunk = MIN(sizeof(buffer), payload_size - offset);
        r = file_read_at(file, FILE_OBJECT_TXN_RECORD_HEADER_SIZE + offset, buffer, chunk);
        if (r == PICOKEYS_OK) {
            r = auth->update(auth->ctx, buffer, chunk);
        }
        offset += chunk;
    }
    memset(buffer, 0, sizeof(buffer));

    if (r == PICOKEYS_OK) {
        r = auth->finish(auth->ctx, tag);
    }
    if (r != PICOKEYS_OK) {
        file_object_txn_auth_abort(auth);
    }
    return r;
}

static int file_object_txn_validate_record(const file_object_txn_layout_t *layout, const file_object_authenticator_t *auth, uint8_t slot, uint32_t generation, uint32_t record_id, uint32_t payload_size, const uint8_t commit_record_tag[FILE_OBJECT_AUTH_TAG_SIZE]) {
    if (slot > 1) {
        return PICOKEYS_WRONG_DATA;
    }

    file_t *file = file_search(layout->record_fid[slot]);
    if (!file_has_data(file)) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    if (payload_size > UINT32_MAX - FILE_OBJECT_TXN_RECORD_HEADER_SIZE - FILE_OBJECT_AUTH_TAG_SIZE || file_get_size(file) != FILE_OBJECT_TXN_RECORD_HEADER_SIZE + payload_size + FILE_OBJECT_AUTH_TAG_SIZE) {
        return PICOKEYS_WRONG_DATA;
    }

    uint8_t header[FILE_OBJECT_TXN_RECORD_HEADER_SIZE];
    int r = file_read_at(file, 0, header, sizeof(header));
    if (r != PICOKEYS_OK) {
        return r;
    }
    if (memcmp(header, file_object_txn_record_magic, sizeof(file_object_txn_record_magic)) != 0 || header[FILE_OBJECT_TXN_VERSION_OFFSET] != FILE_OBJECT_TXN_FORMAT_VERSION || header[FILE_OBJECT_TXN_HEADER_SIZE_OFFSET] != FILE_OBJECT_TXN_RECORD_HEADER_SIZE || header[FILE_OBJECT_TXN_SLOT_OFFSET] != slot || header[FILE_OBJECT_TXN_RECORD_RESERVED_OFFSET] != 0 || get_uint16_be(header + FILE_OBJECT_TXN_NAMESPACE_OFFSET) != layout->namespace_id || get_uint16_be(header + FILE_OBJECT_TXN_TYPE_OFFSET) != layout->object_type || get_uint32_be(header + FILE_OBJECT_TXN_OBJECT_ID_OFFSET) != layout->object_id || get_uint32_be(header + FILE_OBJECT_TXN_GENERATION_OFFSET) != generation || get_uint32_be(header + FILE_OBJECT_TXN_RECORD_ID_OFFSET) != record_id || get_uint32_be(header + FILE_OBJECT_TXN_PAYLOAD_SIZE_OFFSET) != payload_size || get_uint16_be(header + FILE_OBJECT_TXN_RECORD_FID_OFFSET) != layout->record_fid[slot] || get_uint16_be(header + FILE_OBJECT_TXN_RECORD_RESERVED_2_OFFSET) != 0) {
        return PICOKEYS_WRONG_DATA;
    }

    uint8_t calculated_tag[FILE_OBJECT_AUTH_TAG_SIZE];
    uint8_t stored_tag[FILE_OBJECT_AUTH_TAG_SIZE];
    r = file_object_txn_auth_record(auth, file, header, payload_size, calculated_tag);
    if (r == PICOKEYS_OK) {
        r = file_read_at(file, FILE_OBJECT_TXN_RECORD_HEADER_SIZE + payload_size, stored_tag, sizeof(stored_tag));
    }
    if (r == PICOKEYS_OK && (!file_object_txn_tag_equal(calculated_tag, stored_tag) || !file_object_txn_tag_equal(calculated_tag, commit_record_tag))) {
        r = PICOKEYS_WRONG_SIGNATURE;
    }
    memset(calculated_tag, 0, sizeof(calculated_tag));
    memset(stored_tag, 0, sizeof(stored_tag));
    return r;
}

static int file_object_txn_parse_commit(const file_object_txn_layout_t *layout, const file_object_authenticator_t *auth, uint8_t slot, file_object_txn_state_t *state) {
    file_t *file = file_search(layout->commit_fid[slot]);
    if (!file_has_data(file)) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    if (file_get_size(file) != FILE_OBJECT_TXN_COMMIT_SIZE) {
        return PICOKEYS_WRONG_DATA;
    }

    uint8_t commit[FILE_OBJECT_TXN_COMMIT_SIZE];
    int r = file_read_at(file, 0, commit, sizeof(commit));
    if (r != PICOKEYS_OK) {
        return r;
    }
    uint8_t flags = commit[FILE_OBJECT_TXN_COMMIT_FLAGS_OFFSET];
    uint32_t generation = get_uint32_be(commit + FILE_OBJECT_TXN_GENERATION_OFFSET);
    uint32_t record_id = get_uint32_be(commit + FILE_OBJECT_TXN_RECORD_ID_OFFSET);
    uint32_t payload_size = get_uint32_be(commit + FILE_OBJECT_TXN_COMMIT_PAYLOAD_SIZE_OFFSET);
    uint16_t record_fid = get_uint16_be(commit + FILE_OBJECT_TXN_COMMIT_RECORD_FID_OFFSET);
    uint8_t record_slot = commit[FILE_OBJECT_TXN_COMMIT_RECORD_SLOT_OFFSET];
    if (memcmp(commit, file_object_txn_commit_magic, sizeof(file_object_txn_commit_magic)) != 0 || commit[FILE_OBJECT_TXN_VERSION_OFFSET] != FILE_OBJECT_TXN_FORMAT_VERSION || commit[FILE_OBJECT_TXN_HEADER_SIZE_OFFSET] != FILE_OBJECT_TXN_COMMIT_HEADER_SIZE || commit[FILE_OBJECT_TXN_SLOT_OFFSET] != slot || commit[FILE_OBJECT_TXN_COMMIT_MARKER_OFFSET] != FILE_OBJECT_TXN_COMMIT_MARKER || get_uint16_be(commit + FILE_OBJECT_TXN_NAMESPACE_OFFSET) != layout->namespace_id || get_uint16_be(commit + FILE_OBJECT_TXN_TYPE_OFFSET) != layout->object_type || get_uint32_be(commit + FILE_OBJECT_TXN_OBJECT_ID_OFFSET) != layout->object_id || generation == 0 || (flags & ~FILE_OBJECT_TXN_FLAG_DELETED) != 0) {
        return PICOKEYS_WRONG_DATA;
    }

    uint8_t calculated_tag[FILE_OBJECT_AUTH_TAG_SIZE];
    r = file_object_txn_auth_buffer(auth, commit, FILE_OBJECT_TXN_COMMIT_HEADER_SIZE, NULL, 0, calculated_tag);
    if (r == PICOKEYS_OK && !file_object_txn_tag_equal(calculated_tag, commit + FILE_OBJECT_TXN_COMMIT_TAG_OFFSET)) {
        r = PICOKEYS_WRONG_SIGNATURE;
    }
    memset(calculated_tag, 0, sizeof(calculated_tag));
    if (r != PICOKEYS_OK) {
        return r;
    }

    bool deleted = (flags & FILE_OBJECT_TXN_FLAG_DELETED) != 0;
    if (deleted) {
        uint8_t empty_tag[FILE_OBJECT_AUTH_TAG_SIZE] = { 0 };
        if (record_id != 0 || payload_size != 0 || record_fid != 0 || record_slot != UINT8_MAX || !file_object_txn_tag_equal(commit + FILE_OBJECT_TXN_COMMIT_RECORD_TAG_OFFSET, empty_tag)) {
            return PICOKEYS_WRONG_DATA;
        }
    }
    else {
        if (record_slot > 1 || record_fid != layout->record_fid[record_slot] || record_id == 0) {
            return PICOKEYS_WRONG_DATA;
        }
        r = file_object_txn_validate_record(layout, auth, record_slot, generation, record_id, payload_size, commit + FILE_OBJECT_TXN_COMMIT_RECORD_TAG_OFFSET);
        if (r != PICOKEYS_OK) {
            return r;
        }
    }

    *state = (file_object_txn_state_t) { .generation = generation, .record_id = record_id, .payload_size = payload_size, .commit_slot = slot, .record_slot = record_slot, .deleted = deleted };
    return PICOKEYS_OK;
}

static bool file_object_txn_invalid_record(int status) {
    return status == PICOKEYS_ERR_FILE_NOT_FOUND || status == PICOKEYS_WRONG_DATA || status == PICOKEYS_WRONG_SIGNATURE;
}

static int file_object_txn_recover(const file_object_txn_layout_t *layout, const file_object_authenticator_t *auth, file_object_txn_state_t *state) {
    bool found = false;
    file_object_txn_state_t selected = { 0 };
    for (uint8_t slot = 0; slot < 2; slot++) {
        file_object_txn_state_t candidate;
        int r = file_object_txn_parse_commit(layout, auth, slot, &candidate);
        if (file_object_txn_invalid_record(r)) {
            continue;
        }
        if (r != PICOKEYS_OK) {
            return r;
        }
        if (found && candidate.generation == selected.generation) {
            return PICOKEYS_WRONG_DATA;
        }
        if (!found || candidate.generation > selected.generation) {
            selected = candidate;
            found = true;
        }
    }
    if (!found) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    *state = selected;
    return PICOKEYS_OK;
}

static file_object_txn_handle_entry_t *file_object_txn_find_handle(file_object_txn_handle_t handle) {
    if (handle == FILE_OBJECT_TXN_INVALID_HANDLE) {
        return NULL;
    }
    for (size_t i = 0; i < FILE_OBJECT_TXN_MAX_HANDLES; i++) {
        if (file_object_txn_handles[i].token == handle) {
            return &file_object_txn_handles[i];
        }
    }
    return NULL;
}

static file_object_txn_handle_t file_object_txn_allocate_token(void) {
    do {
        file_object_txn_handle_t handle = file_object_txn_next_handle++;
        if (handle != FILE_OBJECT_TXN_INVALID_HANDLE && !file_object_txn_find_handle(handle)) {
            return handle;
        }
    } while (true);
}

static int file_object_txn_resolve(file_object_txn_handle_t handle, const file_object_authenticator_t *auth, file_object_txn_handle_entry_t **entry, file_object_txn_state_t *state) {
    file_object_txn_handle_entry_t *current = file_object_txn_find_handle(handle);
    if (!current) {
        return PICOKEYS_ERR_STALE_HANDLE;
    }

    file_object_txn_state_t recovered;
    int r = file_object_txn_recover(&current->layout, auth, &recovered);
    if (r == PICOKEYS_ERR_FILE_NOT_FOUND || r == PICOKEYS_WRONG_DATA || r == PICOKEYS_WRONG_SIGNATURE) {
        return PICOKEYS_ERR_STALE_HANDLE;
    }
    if (r != PICOKEYS_OK) {
        return r;
    }
    if (recovered.deleted || recovered.generation != current->state.generation || recovered.record_id != current->state.record_id || recovered.record_slot != current->state.record_slot || recovered.payload_size != current->state.payload_size) {
        return PICOKEYS_ERR_STALE_HANDLE;
    }
    if (entry) {
        *entry = current;
    }
    if (state) {
        *state = recovered;
    }
    return PICOKEYS_OK;
}

static int file_object_txn_remove_file(uint16_t fid) {
    file_t *file = file_search(fid);
    if (!file) {
        return PICOKEYS_OK;
    }
    if (file_search_by_fid(fid, NULL, SPECIFY_ANY)) {
        return PICOKEYS_WRONG_DATA;
    }
    return file_delete_no_commit(file);
}

static int file_object_txn_replace_file(uint16_t fid, const uint8_t *data, uint32_t len) {
    int r = file_object_txn_remove_file(fid);
    if (r != PICOKEYS_OK) {
        return r;
    }
    file_t *file = file_new(fid);
    if (!file) {
        return PICOKEYS_ERR_NO_MEMORY;
    }
    return file_put_data(file, data, len);
}

static int file_object_txn_write_record(const file_object_txn_layout_t *layout, const file_object_authenticator_t *auth, uint8_t slot, uint32_t generation, uint32_t record_id, const uint8_t *data, uint32_t len, uint8_t record_tag[FILE_OBJECT_AUTH_TAG_SIZE]) {
    if (len > UINT32_MAX - FILE_OBJECT_TXN_RECORD_HEADER_SIZE - FILE_OBJECT_AUTH_TAG_SIZE) {
        return PICOKEYS_ERR_NO_MEMORY;
    }
    uint32_t record_size = FILE_OBJECT_TXN_RECORD_HEADER_SIZE + len + FILE_OBJECT_AUTH_TAG_SIZE;
    uint8_t *record = (uint8_t *)calloc(1, record_size);
    if (!record) {
        return PICOKEYS_ERR_MEMORY_FATAL;
    }

    memcpy(record, file_object_txn_record_magic, sizeof(file_object_txn_record_magic));
    record[FILE_OBJECT_TXN_VERSION_OFFSET] = FILE_OBJECT_TXN_FORMAT_VERSION;
    record[FILE_OBJECT_TXN_HEADER_SIZE_OFFSET] = FILE_OBJECT_TXN_RECORD_HEADER_SIZE;
    record[FILE_OBJECT_TXN_SLOT_OFFSET] = slot;
    put_uint16_be(layout->namespace_id, record + FILE_OBJECT_TXN_NAMESPACE_OFFSET);
    put_uint16_be(layout->object_type, record + FILE_OBJECT_TXN_TYPE_OFFSET);
    put_uint32_be(layout->object_id, record + FILE_OBJECT_TXN_OBJECT_ID_OFFSET);
    put_uint32_be(generation, record + FILE_OBJECT_TXN_GENERATION_OFFSET);
    put_uint32_be(record_id, record + FILE_OBJECT_TXN_RECORD_ID_OFFSET);
    put_uint32_be(len, record + FILE_OBJECT_TXN_PAYLOAD_SIZE_OFFSET);
    put_uint16_be(layout->record_fid[slot], record + FILE_OBJECT_TXN_RECORD_FID_OFFSET);
    if (len > 0) {
        memcpy(record + FILE_OBJECT_TXN_RECORD_HEADER_SIZE, data, len);
    }

    int r = file_object_txn_auth_buffer(auth, record, FILE_OBJECT_TXN_RECORD_HEADER_SIZE, data, len, record_tag);
    if (r == PICOKEYS_OK) {
        memcpy(record + FILE_OBJECT_TXN_RECORD_HEADER_SIZE + len, record_tag, FILE_OBJECT_AUTH_TAG_SIZE);
        r = file_object_txn_replace_file(layout->record_fid[slot], record, record_size);
    }
    memset(record, 0, record_size);
    free(record);
    return r;
}

static int file_object_txn_write_commit(const file_object_txn_layout_t *layout, const file_object_authenticator_t *auth, uint8_t commit_slot, uint8_t record_slot, uint32_t generation, uint32_t record_id, uint32_t payload_size, const uint8_t record_tag[FILE_OBJECT_AUTH_TAG_SIZE], bool deleted) {
    uint8_t commit[FILE_OBJECT_TXN_COMMIT_SIZE] = { 0 };
    memcpy(commit, file_object_txn_commit_magic, sizeof(file_object_txn_commit_magic));
    commit[FILE_OBJECT_TXN_VERSION_OFFSET] = FILE_OBJECT_TXN_FORMAT_VERSION;
    commit[FILE_OBJECT_TXN_HEADER_SIZE_OFFSET] = FILE_OBJECT_TXN_COMMIT_HEADER_SIZE;
    commit[FILE_OBJECT_TXN_SLOT_OFFSET] = commit_slot;
    commit[FILE_OBJECT_TXN_COMMIT_MARKER_OFFSET] = FILE_OBJECT_TXN_COMMIT_MARKER;
    put_uint16_be(layout->namespace_id, commit + FILE_OBJECT_TXN_NAMESPACE_OFFSET);
    put_uint16_be(layout->object_type, commit + FILE_OBJECT_TXN_TYPE_OFFSET);
    put_uint32_be(layout->object_id, commit + FILE_OBJECT_TXN_OBJECT_ID_OFFSET);
    put_uint32_be(generation, commit + FILE_OBJECT_TXN_GENERATION_OFFSET);
    if (deleted) {
        commit[FILE_OBJECT_TXN_COMMIT_RECORD_SLOT_OFFSET] = UINT8_MAX;
        commit[FILE_OBJECT_TXN_COMMIT_FLAGS_OFFSET] = FILE_OBJECT_TXN_FLAG_DELETED;
    }
    else {
        put_uint32_be(record_id, commit + FILE_OBJECT_TXN_RECORD_ID_OFFSET);
        put_uint16_be(layout->record_fid[record_slot], commit + FILE_OBJECT_TXN_COMMIT_RECORD_FID_OFFSET);
        commit[FILE_OBJECT_TXN_COMMIT_RECORD_SLOT_OFFSET] = record_slot;
        put_uint32_be(payload_size, commit + FILE_OBJECT_TXN_COMMIT_PAYLOAD_SIZE_OFFSET);
        memcpy(commit + FILE_OBJECT_TXN_COMMIT_RECORD_TAG_OFFSET, record_tag, FILE_OBJECT_AUTH_TAG_SIZE);
    }

    int r = file_object_txn_auth_buffer(auth, commit, FILE_OBJECT_TXN_COMMIT_HEADER_SIZE, NULL, 0, commit + FILE_OBJECT_TXN_COMMIT_TAG_OFFSET);
    if (r == PICOKEYS_OK) {
        r = file_object_txn_replace_file(layout->commit_fid[commit_slot], commit, sizeof(commit));
    }
    memset(commit, 0, sizeof(commit));
    return r;
}

static int file_object_txn_next_state(const file_object_txn_layout_t *layout, const file_object_authenticator_t *auth, uint8_t *target_slot, uint32_t *generation) {
    file_object_txn_state_t current;
    int r = file_object_txn_recover(layout, auth, &current);
    if (r == PICOKEYS_ERR_FILE_NOT_FOUND) {
        *target_slot = 0;
        *generation = 1;
        return PICOKEYS_OK;
    }
    if (r != PICOKEYS_OK) {
        return r;
    }
    if (current.generation == UINT32_MAX) {
        return PICOKEYS_WRONG_DATA;
    }
    *target_slot = current.commit_slot ^ 1u;
    *generation = current.generation + 1;
    return PICOKEYS_OK;
}

int file_object_txn_open(const file_object_txn_layout_t *layout, const file_object_authenticator_t *auth, file_object_txn_handle_t *handle) {
    if (!file_object_txn_layout_valid(layout) || !file_object_txn_auth_valid(auth) || !handle) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    *handle = FILE_OBJECT_TXN_INVALID_HANDLE;

    file_object_txn_state_t state;
    int r = file_object_txn_recover(layout, auth, &state);
    if (r != PICOKEYS_OK) {
        return r;
    }
    if (state.deleted) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }

    for (size_t i = 0; i < FILE_OBJECT_TXN_MAX_HANDLES; i++) {
        if (file_object_txn_handles[i].token == FILE_OBJECT_TXN_INVALID_HANDLE) {
            file_object_txn_handles[i] = (file_object_txn_handle_entry_t) { .layout = *layout, .state = state, .token = file_object_txn_allocate_token() };
            *handle = file_object_txn_handles[i].token;
            return PICOKEYS_OK;
        }
    }
    return PICOKEYS_ERR_NO_MEMORY;
}

int file_object_txn_get_info(file_object_txn_handle_t handle, const file_object_authenticator_t *auth, file_object_info_t *info) {
    if (!file_object_txn_auth_valid(auth) || !info) {
        return PICOKEYS_ERR_NULL_PARAM;
    }

    file_object_txn_state_t state;
    int r = file_object_txn_resolve(handle, auth, NULL, &state);
    if (r != PICOKEYS_OK) {
        return r;
    }
    *info = (file_object_info_t) { .payload_size = state.payload_size, .generation = state.generation };
    return PICOKEYS_OK;
}

int file_object_txn_read_at(file_object_txn_handle_t handle, const file_object_authenticator_t *auth, uint32_t offset, uint8_t *data, size_t len) {
    if (!file_object_txn_auth_valid(auth) || (!data && len > 0)) {
        return PICOKEYS_ERR_NULL_PARAM;
    }

    file_object_txn_handle_entry_t *entry = NULL;
    file_object_txn_state_t state;
    int r = file_object_txn_resolve(handle, auth, &entry, &state);
    if (r != PICOKEYS_OK) {
        return r;
    }
    if (offset > state.payload_size || len > state.payload_size - offset) {
        return PICOKEYS_WRONG_LENGTH;
    }

    file_t *file = file_search(entry->layout.record_fid[state.record_slot]);
    return file_read_at(file, FILE_OBJECT_TXN_RECORD_HEADER_SIZE + offset, data, len);
}

int file_object_txn_close(file_object_txn_handle_t handle) {
    file_object_txn_handle_entry_t *entry = file_object_txn_find_handle(handle);
    if (!entry) {
        return PICOKEYS_ERR_STALE_HANDLE;
    }
    memset(entry, 0, sizeof(*entry));
    return PICOKEYS_OK;
}

int file_object_txn_put(const file_object_txn_layout_t *layout, const file_object_authenticator_t *auth, const uint8_t *data, uint32_t len) {
    if (!file_object_txn_layout_valid(layout) || !file_object_txn_auth_valid(auth) || (!data && len > 0)) {
        return PICOKEYS_ERR_NULL_PARAM;
    }

    uint8_t target_slot = 0;
    uint32_t generation = 0;
    int r = file_object_txn_next_state(layout, auth, &target_slot, &generation);
    if (r != PICOKEYS_OK) {
        return r;
    }
    r = file_object_txn_remove_file(layout->commit_fid[target_slot]);
    if (r == PICOKEYS_OK) {
        r = file_object_txn_remove_file(layout->record_fid[target_slot]);
    }

    uint8_t record_tag[FILE_OBJECT_AUTH_TAG_SIZE] = { 0 };
    if (r == PICOKEYS_OK) {
        r = file_object_txn_write_record(layout, auth, target_slot, generation, generation, data, len, record_tag);
    }
    if (r == PICOKEYS_OK && !flash_commit_sync(FILE_OBJECT_TXN_COMMIT_TIMEOUT_MS)) {
        r = PICOKEYS_ERR_MEMORY_FATAL;
    }
    if (r == PICOKEYS_OK) {
        r = file_object_txn_write_commit(layout, auth, target_slot, target_slot, generation, generation, len, record_tag, false);
    }
    memset(record_tag, 0, sizeof(record_tag));
    if (r == PICOKEYS_OK && !flash_commit_sync(FILE_OBJECT_TXN_COMMIT_TIMEOUT_MS)) {
        r = PICOKEYS_ERR_MEMORY_FATAL;
    }
    return r;
}

int file_object_txn_delete(const file_object_txn_layout_t *layout, const file_object_authenticator_t *auth) {
    if (!file_object_txn_layout_valid(layout) || !file_object_txn_auth_valid(auth)) {
        return PICOKEYS_ERR_NULL_PARAM;
    }

    file_object_txn_state_t current;
    int r = file_object_txn_recover(layout, auth, &current);
    if (r != PICOKEYS_OK) {
        return r;
    }
    if (current.deleted || current.generation == UINT32_MAX) {
        return current.deleted ? PICOKEYS_ERR_FILE_NOT_FOUND : PICOKEYS_WRONG_DATA;
    }

    uint8_t target_slot = current.commit_slot ^ 1u;
    r = file_object_txn_remove_file(layout->commit_fid[target_slot]);
    if (r == PICOKEYS_OK) {
        r = file_object_txn_remove_file(layout->record_fid[target_slot]);
    }
    if (r == PICOKEYS_OK && !flash_commit_sync(FILE_OBJECT_TXN_COMMIT_TIMEOUT_MS)) {
        r = PICOKEYS_ERR_MEMORY_FATAL;
    }
    if (r == PICOKEYS_OK) {
        const uint8_t empty_tag[FILE_OBJECT_AUTH_TAG_SIZE] = { 0 };
        r = file_object_txn_write_commit(layout, auth, target_slot, UINT8_MAX, current.generation + 1, 0, 0, empty_tag, true);
    }
    if (r == PICOKEYS_OK && !flash_commit_sync(FILE_OBJECT_TXN_COMMIT_TIMEOUT_MS)) {
        r = PICOKEYS_ERR_MEMORY_FATAL;
    }
    return r;
}
