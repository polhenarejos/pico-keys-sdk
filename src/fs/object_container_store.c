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
#include "object_container_store.h"

#define FILE_OBJECT_CONTAINER_MAX_MANIFEST_SIZE (FILE_OBJECT_MANIFEST_HEADER_SIZE + FILE_OBJECT_MANIFEST_MAX_OBJECTS * FILE_OBJECT_DESCRIPTOR_SIZE + FILE_OBJECT_AUTH_TAG_SIZE)

static bool file_object_container_layout_valid(const file_object_container_layout_t *layout) {
    return layout && layout->namespace_id != 0 && layout->container_kind != 0 && layout->commit_timeout_ms > 0 && layout->manifest_fid && layout->record_fid && layout->record_allocate && layout->policy_hash;
}

static bool file_object_container_crypto_valid(const file_object_container_crypto_t *crypto) {
    return crypto && crypto->auth && crypto->protector;
}

static file_object_container_candidate_t *file_object_container_current(file_object_container_state_t *state) {
    if (!state || state->current_slot >= FILE_OBJECT_CONTAINER_SLOT_COUNT) {
        return NULL;
    }
    return &state->candidates[state->current_slot];
}

static int file_object_container_replace_file(uint16_t fid, const_byte_array_t data) {
    file_t *file = file_search(fid);
    if (file && file_delete_no_commit(file) != PICOKEYS_OK) {
        return PICOKEYS_EXEC_ERROR;
    }
    file = file_new(fid);
    if (!file) {
        return PICOKEYS_ERR_NO_MEMORY;
    }
    return file_put_data(file, data);
}

static int file_object_container_parse_slot(const file_object_container_layout_t *layout, uint32_t container_id, uint8_t slot, const file_object_authenticator_t *auth, file_object_container_candidate_t *candidate) {
    memset(candidate, 0, sizeof(*candidate));
    uint16_t manifest_fid = layout->manifest_fid(layout->ctx, container_id, slot);
    file_t *file = file_search(manifest_fid);
    if (!file_has_data(file)) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    int r = file_object_manifest_parse(CONST_BYTE_ARRAY(file_get_data(file), file_get_size(file)), auth, NULL, NULL, &candidate->manifest);
    if (r != PICOKEYS_OK) {
        return r;
    }
    if (candidate->manifest.namespace_id != layout->namespace_id || candidate->manifest.container_kind != layout->container_kind || candidate->manifest.container_id != container_id || candidate->manifest.object_count == 0) {
        return PICOKEYS_WRONG_DATA;
    }
    for (uint16_t i = 0; i < candidate->manifest.object_count; i++) {
        const file_object_descriptor_t *object = &candidate->manifest.objects[i];
        if (layout->descriptor_valid && !layout->descriptor_valid(layout->ctx, container_id, object)) {
            return PICOKEYS_WRONG_DATA;
        }
        uint16_t record_fid = 0;
        r = layout->record_fid(layout->ctx, container_id, object, &record_fid);
        if (r != PICOKEYS_OK) {
            return r;
        }
        file_t *record = file_search(record_fid);
        file_object_record_info_t info;
        if (!file_has_data(record) || file_object_record_header_parse(CONST_BYTE_ARRAY(file_get_data(record), file_get_size(record)), object, &info) != PICOKEYS_OK) {
            return PICOKEYS_WRONG_DATA;
        }
    }
    candidate->slot = slot;
    candidate->valid = true;
    return PICOKEYS_OK;
}

static int file_object_container_load_with_crypto(const file_object_container_layout_t *layout, uint32_t container_id, const file_object_container_crypto_t *crypto, file_object_container_state_t *state) {
    bool found = false;
    bool storage_present = false;
    memset(state, 0, sizeof(*state));
    state->current_slot = FILE_OBJECT_CONTAINER_INVALID_SLOT;
    state->crypto = *crypto;

    for (uint8_t slot = 0; slot < FILE_OBJECT_CONTAINER_SLOT_COUNT; slot++) {
        storage_present |= file_has_data(file_search(layout->manifest_fid(layout->ctx, container_id, slot)));
        int r = file_object_container_parse_slot(layout, container_id, slot, crypto->auth, &state->candidates[slot]);
        if (r == PICOKEYS_OK) {
            if (state->current_slot != FILE_OBJECT_CONTAINER_INVALID_SLOT && state->candidates[state->current_slot].manifest.generation == state->candidates[slot].manifest.generation) {
                return PICOKEYS_WRONG_DATA;
            }
            if (state->current_slot == FILE_OBJECT_CONTAINER_INVALID_SLOT || state->candidates[slot].manifest.generation > state->candidates[state->current_slot].manifest.generation) {
                state->current_slot = slot;
            }
            found = true;
        }
        else if (r != PICOKEYS_ERR_FILE_NOT_FOUND && r != PICOKEYS_WRONG_DATA && r != PICOKEYS_WRONG_SIGNATURE) {
            return r;
        }
    }
    if (!found) {
        return storage_present ? PICOKEYS_WRONG_DATA : PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    return PICOKEYS_OK;
}

int file_object_container_load(const file_object_container_layout_t *layout, uint32_t container_id, const file_object_container_crypto_t *primary, const file_object_container_crypto_t *legacy, file_object_container_state_t *state) {
    if (!file_object_container_layout_valid(layout) || !file_object_container_crypto_valid(primary) || !state) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    int r = file_object_container_load_with_crypto(layout, container_id, primary, state);
    if (r == PICOKEYS_OK || r == PICOKEYS_ERR_FILE_NOT_FOUND || !file_object_container_crypto_valid(legacy)) {
        return r;
    }

    file_object_container_state_t legacy_state;
    int legacy_result = file_object_container_load_with_crypto(layout, container_id, legacy, &legacy_state);
    if (legacy_result != PICOKEYS_OK) {
        return r;
    }
    *state = legacy_state;
    return PICOKEYS_OK;
}

const file_object_descriptor_t *file_object_container_find(const file_object_manifest_t *manifest, uint16_t object_type, uint16_t object_tag) {
    if (!manifest) {
        return NULL;
    }
    for (uint16_t i = 0; i < manifest->object_count; i++) {
        if (manifest->objects[i].object_type == object_type && manifest->objects[i].object_tag == object_tag) {
            return &manifest->objects[i];
        }
    }
    return NULL;
}

bool file_object_container_references(const file_object_manifest_t *manifest, uint64_t record_id) {
    if (!manifest) {
        return false;
    }
    for (uint16_t i = 0; i < manifest->object_count; i++) {
        if (manifest->objects[i].record_id == record_id) {
            return true;
        }
    }
    return false;
}

static int file_object_container_unseal(const file_object_container_layout_t *layout, uint32_t container_id, const file_object_manifest_t *manifest, const file_object_descriptor_t *object, const file_object_record_protector_t *protector, byte_buffer_t *data) {
    file_object_manifest_t record_manifest = *manifest;
    record_manifest.object_count = 1;
    record_manifest.has_object = true;
    record_manifest.object = *object;

    uint8_t policy_hash[FILE_OBJECT_POLICY_HASH_SIZE];
    int r = layout->policy_hash(layout->ctx, object->policy_id, policy_hash);
    if (r != PICOKEYS_OK) {
        return r;
    }
    uint16_t record_fid = 0;
    r = layout->record_fid(layout->ctx, container_id, object, &record_fid);
    if (r != PICOKEYS_OK) {
        return r;
    }
    file_t *record = file_search(record_fid);
    if (!file_has_data(record)) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    r = file_object_record_unseal(&record_manifest, policy_hash, protector, CONST_BYTE_ARRAY(file_get_data(record), file_get_size(record)), data);
    memset(policy_hash, 0, sizeof(policy_hash));
    return r;
}

int file_object_container_validate(const file_object_container_layout_t *layout, uint32_t container_id, const file_object_container_candidate_t *candidate, const file_object_record_protector_t *protector) {
    if (!file_object_container_layout_valid(layout) || !candidate || !candidate->valid || !protector) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    for (uint16_t i = 0; i < candidate->manifest.object_count; i++) {
        const file_object_descriptor_t *object = &candidate->manifest.objects[i];
        uint8_t *plaintext = NULL;
        if (object->logical_size > 0) {
            plaintext = (uint8_t *)calloc(1, object->logical_size);
            if (!plaintext) {
                return PICOKEYS_ERR_MEMORY_FATAL;
            }
        }
        byte_buffer_t output = BYTE_BUFFER(plaintext, object->logical_size);
        int r = file_object_container_unseal(layout, container_id, &candidate->manifest, object, protector, &output);
        if (plaintext) {
            memset(plaintext, 0, object->logical_size);
            free(plaintext);
        }
        if (r != PICOKEYS_OK || output.len != object->logical_size) {
            return r == PICOKEYS_OK ? PICOKEYS_WRONG_LENGTH : r;
        }
    }
    return PICOKEYS_OK;
}

static int file_object_container_select_valid(const file_object_container_layout_t *layout, uint32_t container_id, file_object_container_state_t *state) {
    file_object_container_candidate_t *current = file_object_container_current(state);
    if (!current) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    int r = file_object_container_validate(layout, container_id, current, state->crypto.protector);
    file_object_container_candidate_t *previous = &state->candidates[current->slot ^ 1u];
    if (r != PICOKEYS_OK && previous->valid && file_object_container_validate(layout, container_id, previous, state->crypto.protector) == PICOKEYS_OK) {
        state->current_slot = previous->slot;
        return PICOKEYS_OK;
    }
    return r;
}

int file_object_container_object_size(const file_object_container_layout_t *layout, uint32_t container_id, uint16_t object_type, uint16_t object_tag, const file_object_container_crypto_t *primary, const file_object_container_crypto_t *legacy, file_object_container_access_t access, void *access_ctx, uint32_t *object_size) {
    if (!object_size) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    *object_size = 0;
    file_object_container_state_t state;
    int r = file_object_container_load(layout, container_id, primary, legacy, &state);
    if (r != PICOKEYS_OK) {
        return r;
    }
    const file_object_descriptor_t *object = file_object_container_find(&state.candidates[state.current_slot].manifest, object_type, object_tag);
    if (!object) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    if (access) {
        r = access(access_ctx, object);
        if (r != PICOKEYS_OK) {
            return r;
        }
    }
    *object_size = object->logical_size;
    return PICOKEYS_OK;
}

int file_object_container_read(const file_object_container_layout_t *layout, uint32_t container_id, uint16_t object_type, uint16_t object_tag, const file_object_container_crypto_t *primary, const file_object_container_crypto_t *legacy, file_object_container_access_t access, void *access_ctx, byte_buffer_t *data) {
    if (!data || data->len > data->capacity || (!data->data && data->capacity > 0)) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    file_object_container_state_t state;
    int r = file_object_container_load(layout, container_id, primary, legacy, &state);
    if (r != PICOKEYS_OK) {
        return r;
    }
    const file_object_descriptor_t *current_object = file_object_container_find(&state.candidates[state.current_slot].manifest, object_type, object_tag);
    if (!current_object) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    for (uint8_t attempt = 0; attempt < FILE_OBJECT_CONTAINER_SLOT_COUNT; attempt++) {
        uint8_t slot = attempt == 0 ? state.current_slot : state.current_slot ^ 1u;
        file_object_container_candidate_t *candidate = &state.candidates[slot];
        if (!candidate->valid) {
            continue;
        }
        const file_object_descriptor_t *object = attempt == 0 ? current_object : file_object_container_find(&candidate->manifest, object_type, object_tag);
        if (!object) {
            continue;
        }
        if (access) {
            r = access(access_ctx, object);
            if (r != PICOKEYS_OK) {
                return r;
            }
        }
        r = file_object_container_unseal(layout, container_id, &candidate->manifest, object, state.crypto.protector, data);
        if (r == PICOKEYS_OK) {
            return PICOKEYS_OK;
        }
    }
    if (data->data && data->capacity > data->len) {
        memset(data->data + data->len, 0, data->capacity - data->len);
    }
    return r;
}

static int file_object_container_descriptor_compare(const void *left, const void *right) {
    const file_object_descriptor_t *a = (const file_object_descriptor_t *)left;
    const file_object_descriptor_t *b = (const file_object_descriptor_t *)right;
    if (a->object_type != b->object_type) {
        return a->object_type < b->object_type ? -1 : 1;
    }
    if (a->object_tag != b->object_tag) {
        return a->object_tag < b->object_tag ? -1 : 1;
    }
    return 0;
}

static int file_object_container_write_record(const file_object_container_layout_t *layout, uint32_t container_id, uint8_t target_slot, const file_object_container_write_t *write, uint32_t object_generation, const file_object_manifest_t *next, const file_object_container_crypto_t *crypto, file_object_descriptor_t *descriptor, uint16_t *record_fid) {
    uint64_t record_id = 0;
    int r = layout->record_allocate(layout->ctx, container_id, target_slot, write, crypto->auth, &record_id, record_fid);
    if (r != PICOKEYS_OK) {
        return r;
    }
    *descriptor = (file_object_descriptor_t) {
        .object_type = write->object_type,
        .object_tag = write->object_tag,
        .generation = object_generation,
        .logical_size = (uint32_t)write->data.len,
        .record_id = record_id,
        .stored_size = (uint32_t)write->data.len,
        .policy_id = write->policy_id,
        .key_domain = write->key_domain,
        .protection = write->protection,
        .flags = write->flags,
        .transaction_group = write->transaction_group
    };
    file_object_manifest_t record_manifest = *next;
    record_manifest.object_count = 1;
    record_manifest.has_object = true;
    record_manifest.object = *descriptor;

    uint8_t policy_hash[FILE_OBJECT_POLICY_HASH_SIZE];
    r = layout->policy_hash(layout->ctx, write->policy_id, policy_hash);
    if (r != PICOKEYS_OK) {
        return r;
    }
    if (write->data.len > UINT32_MAX - FILE_OBJECT_RECORD_HEADER_SIZE - FILE_OBJECT_AUTH_TAG_SIZE) {
        memset(policy_hash, 0, sizeof(policy_hash));
        return PICOKEYS_WRONG_LENGTH;
    }
    size_t record_size = FILE_OBJECT_RECORD_HEADER_SIZE + write->data.len + FILE_OBJECT_AUTH_TAG_SIZE;
    uint8_t *record = (uint8_t *)calloc(1, record_size);
    if (!record) {
        memset(policy_hash, 0, sizeof(policy_hash));
        return PICOKEYS_ERR_MEMORY_FATAL;
    }
    byte_buffer_t output = BYTE_BUFFER(record, record_size);
    r = file_object_record_seal(&record_manifest, policy_hash, crypto->protector, write->data, &output);
    if (r == PICOKEYS_OK && output.len != record_size) {
        r = PICOKEYS_WRONG_LENGTH;
    }
    if (r == PICOKEYS_OK) {
        r = file_object_container_replace_file(*record_fid, CONST_BYTE_ARRAY(record, record_size));
    }
    memset(policy_hash, 0, sizeof(policy_hash));
    memset(record, 0, record_size);
    free(record);
    return r;
}

static void file_object_container_rollback(const uint16_t *record_fids, size_t record_count) {
    for (size_t i = 0; i < record_count; i++) {
        file_t *record = file_search(record_fids[i]);
        if (record) {
            file_delete_no_commit(record);
        }
    }
    flash_commit();
}

int file_object_container_update(const file_object_container_layout_t *layout, uint32_t container_id, const file_object_container_write_t *writes, size_t write_count, const file_object_container_crypto_t *primary, const file_object_container_crypto_t *legacy) {
    if (!file_object_container_layout_valid(layout) || !file_object_container_crypto_valid(primary) || !writes || write_count == 0 || write_count > FILE_OBJECT_MANIFEST_MAX_OBJECTS) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    file_object_container_state_t state;
    int r = file_object_container_load(layout, container_id, primary, legacy, &state);
    if (r != PICOKEYS_OK && r != PICOKEYS_ERR_FILE_NOT_FOUND) {
        return r;
    }
    bool creating = r == PICOKEYS_ERR_FILE_NOT_FOUND;
    if (creating) {
        memset(&state, 0, sizeof(state));
        state.current_slot = FILE_OBJECT_CONTAINER_INVALID_SLOT;
        state.crypto = *primary;
    }
    else {
        r = file_object_container_select_valid(layout, container_id, &state);
        if (r != PICOKEYS_OK) {
            return r;
        }
    }
    r = PICOKEYS_OK;

    file_object_container_candidate_t *current = file_object_container_current(&state);
    file_object_manifest_t next = { 0 };
    if (current) {
        next = current->manifest;
        if (next.generation == UINT32_MAX || next.extension_size != 0) {
            return PICOKEYS_WRONG_DATA;
        }
        for (uint16_t i = 0; i < next.object_count; i++) {
            if (next.objects[i].extension_size != 0) {
                return PICOKEYS_WRONG_DATA;
            }
        }
        next.previous_generation = next.generation;
        next.generation++;
    }
    else {
        next.namespace_id = layout->namespace_id;
        next.container_kind = layout->container_kind;
        next.container_id = container_id;
        next.generation = 1;
    }
    uint8_t target_slot = current ? current->slot ^ 1u : 0;
    uint16_t new_record_fids[FILE_OBJECT_MANIFEST_MAX_OBJECTS] = { 0 };
    size_t new_record_count = 0;

    for (size_t i = 0; i < write_count; i++) {
        const file_object_container_write_t *write = &writes[i];
        if ((!write->data.data && write->data.len > 0) || write->object_type == 0 || write->object_type == UINT16_MAX || (write->flags & FILE_OBJECT_FLAG_INLINE) != 0 || (layout->write_valid && !layout->write_valid(layout->ctx, write))) {
            r = PICOKEYS_WRONG_DATA;
            break;
        }
        for (size_t j = 0; j < i; j++) {
            if (writes[j].object_type == write->object_type && writes[j].object_tag == write->object_tag) {
                r = PICOKEYS_WRONG_DATA;
                break;
            }
        }
        if (r != PICOKEYS_OK) {
            break;
        }
        const file_object_descriptor_t *found = file_object_container_find(&next, write->object_type, write->object_tag);
        file_object_descriptor_t *object = (file_object_descriptor_t *)found;
        uint32_t object_generation = object ? object->generation + 1u : 1u;
        if (object && object->generation == UINT32_MAX) {
            r = PICOKEYS_WRONG_DATA;
            break;
        }
        file_object_descriptor_t replacement;
        uint16_t record_fid = 0;
        r = file_object_container_write_record(layout, container_id, target_slot, write, object_generation, &next, &state.crypto, &replacement, &record_fid);
        if (r != PICOKEYS_OK) {
            break;
        }
        new_record_fids[new_record_count++] = record_fid;
        if (object) {
            *object = replacement;
        }
        else if (next.object_count < FILE_OBJECT_MANIFEST_MAX_OBJECTS) {
            next.objects[next.object_count++] = replacement;
            next.has_object = true;
        }
        else {
            r = PICOKEYS_ERR_NO_MEMORY;
            break;
        }
    }
    if (r == PICOKEYS_OK && !flash_commit_sync(layout->commit_timeout_ms)) {
        r = PICOKEYS_ERR_MEMORY_FATAL;
    }
    if (r != PICOKEYS_OK) {
        if (layout->rollback_new_records) {
            file_object_container_rollback(new_record_fids, new_record_count);
        }
        return r;
    }

    qsort(next.objects, next.object_count, sizeof(next.objects[0]), file_object_container_descriptor_compare);
    uint8_t manifest_data[FILE_OBJECT_CONTAINER_MAX_MANIFEST_SIZE];
    byte_buffer_t manifest = BYTE_BUFFER(manifest_data, sizeof(manifest_data));
    r = file_object_manifest_build(&next, CONST_BYTE_ARRAY(NULL, 0), state.crypto.auth, &manifest);
    if (r == PICOKEYS_OK) {
        r = file_object_container_replace_file(layout->manifest_fid(layout->ctx, container_id, target_slot), CONST_BYTE_ARRAY(manifest_data, manifest.len));
    }
    memset(manifest_data, 0, sizeof(manifest_data));
    if (r == PICOKEYS_OK && !flash_commit_sync(layout->commit_timeout_ms)) {
        r = PICOKEYS_ERR_MEMORY_FATAL;
    }
    if (r != PICOKEYS_OK) {
        if (layout->rollback_new_records) {
            file_object_container_rollback(new_record_fids, new_record_count);
        }
        return r;
    }
    if (layout->activate) {
        r = layout->activate(layout->ctx, container_id);
        if (r != PICOKEYS_OK) {
            return r;
        }
    }
    if (layout->retire) {
        r = layout->retire(layout->ctx, container_id, &state, &next, current ? current->slot : FILE_OBJECT_CONTAINER_INVALID_SLOT, target_slot);
        if (r != PICOKEYS_OK) {
            return r;
        }
    }
    return PICOKEYS_OK;
}

int file_object_container_remove(const file_object_container_layout_t *layout, uint32_t container_id, uint16_t object_type, uint16_t object_tag, const file_object_container_crypto_t *primary, const file_object_container_crypto_t *legacy) {
    if (!file_object_container_layout_valid(layout) || !file_object_container_crypto_valid(primary)) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    file_object_container_state_t state;
    int r = file_object_container_load(layout, container_id, primary, legacy, &state);
    if (r != PICOKEYS_OK) {
        return r;
    }
    r = file_object_container_select_valid(layout, container_id, &state);
    if (r != PICOKEYS_OK) {
        return r;
    }
    file_object_container_candidate_t *current = file_object_container_current(&state);
    file_object_manifest_t next = current->manifest;
    const file_object_descriptor_t *found = file_object_container_find(&next, object_type, object_tag);
    if (!found) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    if (next.generation == UINT32_MAX || next.object_count <= 1 || next.extension_size != 0 || found->extension_size != 0) {
        return PICOKEYS_WRONG_DATA;
    }
    size_t object_index = (size_t)(found - next.objects);
    memmove(&next.objects[object_index], &next.objects[object_index + 1], (next.object_count - object_index - 1u) * sizeof(next.objects[0]));
    memset(&next.objects[next.object_count - 1u], 0, sizeof(next.objects[0]));
    next.object_count--;
    next.previous_generation = next.generation;
    next.generation++;

    uint8_t target_slot = current->slot ^ 1u;
    uint8_t manifest_data[FILE_OBJECT_CONTAINER_MAX_MANIFEST_SIZE];
    byte_buffer_t manifest = BYTE_BUFFER(manifest_data, sizeof(manifest_data));
    r = file_object_manifest_build(&next, CONST_BYTE_ARRAY(NULL, 0), state.crypto.auth, &manifest);
    if (r == PICOKEYS_OK) {
        r = file_object_container_replace_file(layout->manifest_fid(layout->ctx, container_id, target_slot), CONST_BYTE_ARRAY(manifest_data, manifest.len));
    }
    memset(manifest_data, 0, sizeof(manifest_data));
    if (r == PICOKEYS_OK && !flash_commit_sync(layout->commit_timeout_ms)) {
        r = PICOKEYS_ERR_MEMORY_FATAL;
    }
    if (r != PICOKEYS_OK) {
        return r;
    }
    if (layout->retire) {
        return layout->retire(layout->ctx, container_id, &state, &next, current->slot, target_slot);
    }
    return PICOKEYS_OK;
}

int file_object_container_delete(const file_object_container_layout_t *layout, uint32_t container_id, const file_object_container_crypto_t *primary, const file_object_container_crypto_t *legacy) {
    if (!file_object_container_layout_valid(layout) || !file_object_container_crypto_valid(primary)) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    file_object_container_state_t state;
    int r = file_object_container_load(layout, container_id, primary, legacy, &state);
    if (r != PICOKEYS_OK) {
        return r;
    }
    for (uint8_t slot = 0; slot < FILE_OBJECT_CONTAINER_SLOT_COUNT; slot++) {
        if (state.candidates[slot].valid) {
            for (uint16_t i = 0; i < state.candidates[slot].manifest.object_count; i++) {
                uint16_t record_fid = 0;
                r = layout->record_fid(layout->ctx, container_id, &state.candidates[slot].manifest.objects[i], &record_fid);
                if (r != PICOKEYS_OK) {
                    return r;
                }
                file_t *record = file_search(record_fid);
                if (record) {
                    file_delete_no_commit(record);
                }
            }
        }
        file_t *manifest = file_search(layout->manifest_fid(layout->ctx, container_id, slot));
        if (manifest) {
            file_delete_no_commit(manifest);
        }
    }
    if (layout->deactivate) {
        r = layout->deactivate(layout->ctx, container_id);
        if (r != PICOKEYS_OK) {
            return r;
        }
    }
    return flash_commit_sync(layout->commit_timeout_ms) ? PICOKEYS_OK : PICOKEYS_ERR_MEMORY_FATAL;
}
