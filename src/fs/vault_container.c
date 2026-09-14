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

#include "vault_container.h"

#include <string.h>

#include "picokeys.h"
#include "flash.h"
#include "object_policy.h"

static bool vault_record_valid(const uint8_t *record, size_t record_len) {
    return record && record_len == PICOKEYS_VAULT_RECORD_SIZE && record[0] == PICOKEYS_VAULT_RECORD_FORMAT;
}

static const uint8_t *vault_legacy_record(const file_t *file) {
    if (!file || !file_has_data(file) || file_get_size(file) != PICOKEYS_VAULT_RECORD_SIZE) {
        return NULL;
    }
    const uint8_t *record = file_get_data(file);
    return vault_record_valid(record, PICOKEYS_VAULT_RECORD_SIZE) ? record : NULL;
}

static int vault_wrap(const uint8_t wrapping_key[PICOKEYS_VAULT_KEY_SIZE], const uint8_t kvault[PICOKEYS_VAULT_KEY_SIZE], uint8_t record[PICOKEYS_VAULT_RECORD_SIZE]) {
    if (!wrapping_key || !kvault || !record) {
        log_errstr("vault container wrap: invalid arguments wrapping_key=%p kvault=%p record=%p", (void *)wrapping_key, (void *)kvault, (void *)record);
        return PICOKEYS_ERR_NULL_PARAM;
    }

    record[0] = PICOKEYS_VAULT_RECORD_FORMAT;
    int ret = encrypt_with_aad(wrapping_key, CONST_BYTE_ARRAY(kvault, PICOKEYS_VAULT_KEY_SIZE), PICOKEYS_VAULT_RECORD_FORMAT, record + 1);
    if (ret != PICOKEYS_OK) {
        log_errstr("vault container wrap: encryption failed ret=%d", ret);
    }
    return ret;
}

static int vault_unwrap(const uint8_t wrapping_key[PICOKEYS_VAULT_KEY_SIZE], const uint8_t record[PICOKEYS_VAULT_RECORD_SIZE], uint8_t kvault[PICOKEYS_VAULT_KEY_SIZE]) {
    if (!wrapping_key || !record || !kvault) {
        log_errstr("vault container unwrap: invalid arguments wrapping_key=%p record=%p kvault=%p", (void *)wrapping_key, (void *)record, (void *)kvault);
        return PICOKEYS_ERR_NULL_PARAM;
    }
    if (record[0] != PICOKEYS_VAULT_RECORD_FORMAT) {
        log_errstr("vault container unwrap: invalid record format actual=%u expected=%u", record[0], PICOKEYS_VAULT_RECORD_FORMAT);
        return PICOKEYS_WRONG_DATA;
    }

    int ret = decrypt_with_aad(wrapping_key, CONST_BYTE_ARRAY(record + 1, PICOKEYS_VAULT_RECORD_SIZE - 1), PICOKEYS_VAULT_RECORD_FORMAT, kvault);
    if (ret != PICOKEYS_OK) {
        log_errstr("vault container unwrap: decryption failed ret=%d", ret);
    }
    return ret;
}

static int vault_clear_legacy_record(file_t *file) {
    if (!file) {
        return PICOKEYS_OK;
    }
    if (!file_has_data(file)) {
        meta_delete_no_commit(file->fid);
        return PICOKEYS_OK;
    }

    if (!vault_legacy_record(file)) {
        log_errstr("vault legacy cleanup: invalid record file=%p size=%zu", (void *)file, file_get_size(file));
        return PICOKEYS_WRONG_DATA;
    }
    int ret = flash_clear_file(file);
    if (ret != PICOKEYS_OK) {
        log_errstr("vault legacy cleanup: file clear failed ret=%d", ret);
    }
    return ret;
}

/* The object layout is shared by all applications using the SDK vault. */
#define PICOKEYS_VAULT_NAMESPACE 0x0002u
#define PICOKEYS_VAULT_CONTAINER_KIND 0x0002u
#define PICOKEYS_VAULT_CONTAINER_ID 0u
#define PICOKEYS_VAULT_WRAP_SIZE PICOKEYS_VAULT_RECORD_SIZE
#define PICOKEYS_VAULT_WRAP_PROTECTION FILE_OBJECT_PROTECTION_AEAD_SECRET
#define PICOKEYS_VAULT_WRAP_FLAGS (FILE_OBJECT_FLAG_MUTABLE | FILE_OBJECT_FLAG_NON_EXPORTABLE)
#define PICOKEYS_VAULT_LABEL_PROTECTION FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC
#define PICOKEYS_VAULT_LABEL_FLAGS FILE_OBJECT_FLAG_MUTABLE

typedef struct picokeys_vault_state {
    const file_object_container_layout_t *layout;
    file_object_container_crypto_t primary;
    file_object_container_crypto_t legacy;
    bool has_legacy;
    file_t *legacy_file;
    file_t *legacy_label_file;
    bool initialized;
} picokeys_vault_state_t;

static const uint8_t vault_internal_policy[] = {
    FILE_OBJECT_POLICY_FORMAT_VERSION, 1,
    0x1f, 0xff, 0x00, 0x00, 0x04, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00
};

static picokeys_vault_state_t vault_state;
static const file_object_container_layout_t vault_layout;

static bool vault_state_valid(void) {
    return vault_state.initialized && vault_state.layout && vault_state.primary.auth && vault_state.primary.protector;
}

static uint16_t vault_manifest_fid(uint8_t slot) {
    return (uint16_t)((slot == 0 ? 0xc4u : 0xc5u) << 8);
}

static uint16_t vault_record_fid(uint8_t slot, uint16_t object_type, uint8_t object_tag) {
    uint8_t prefix;
    if (object_type == PICOKEYS_VAULT_OBJECT_WRAP) {
        prefix = slot == 0 ? 0xc6u : 0xc7u;
    }
    else {
        prefix = slot == 0 ? 0xc8u : 0xc9u;
    }
    return (uint16_t)((prefix << 8) | object_tag);
}

static bool vault_object_type_valid(uint16_t object_type) {
    return object_type == PICOKEYS_VAULT_OBJECT_WRAP || object_type == PICOKEYS_VAULT_OBJECT_LABEL;
}

static bool vault_record_id_valid(const file_object_descriptor_t *object) {
    if (!object || !vault_object_type_valid(object->object_type) || object->object_tag > UINT8_MAX || (object->object_type == PICOKEYS_VAULT_OBJECT_LABEL && object->object_tag != 0) || object->record_id > UINT16_MAX) {
        return false;
    }
    uint16_t record_fid = (uint16_t)object->record_id;
    return record_fid == vault_record_fid(0, object->object_type, (uint8_t)object->object_tag) || record_fid == vault_record_fid(1, object->object_type, (uint8_t)object->object_tag);
}

static uint16_t vault_layout_manifest_fid(void *ctx, uint32_t container_id, uint8_t slot) {
    (void)ctx;
    return container_id == PICOKEYS_VAULT_CONTAINER_ID ? vault_manifest_fid(slot) : 0;
}

static int vault_layout_record_fid(void *ctx, uint32_t container_id, const file_object_descriptor_t *object, uint16_t *fid) {
    (void)ctx;
    if (!fid || container_id != PICOKEYS_VAULT_CONTAINER_ID || !vault_record_id_valid(object)) {
        return PICOKEYS_WRONG_DATA;
    }
    *fid = (uint16_t)object->record_id;
    return PICOKEYS_OK;
}

static int vault_layout_record_allocate(void *ctx, uint32_t container_id, uint8_t target_slot, const file_object_container_write_t *write, const file_object_authenticator_t *auth, uint64_t *record_id, uint16_t *fid) {
    (void)ctx;
    (void)auth;
    if (!write || !record_id || !fid || container_id != PICOKEYS_VAULT_CONTAINER_ID || !vault_object_type_valid(write->object_type) || write->object_tag > UINT8_MAX || (write->object_type == PICOKEYS_VAULT_OBJECT_LABEL && write->object_tag != 0)) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    *fid = vault_record_fid(target_slot, write->object_type, (uint8_t)write->object_tag);
    *record_id = *fid;
    return PICOKEYS_OK;
}

static int vault_policy_hash(void *ctx, uint16_t policy_id, uint8_t hash[FILE_OBJECT_POLICY_HASH_SIZE]) {
    (void)ctx;
    if (!hash || policy_id != PICOKEYS_VAULT_POLICY_ID) {
        return PICOKEYS_WRONG_DATA;
    }
    return file_object_policy_hash(CONST_BYTE_ARRAY(vault_internal_policy, sizeof(vault_internal_policy)), hash);
}

static bool vault_write_valid(void *ctx, const file_object_container_write_t *write) {
    (void)ctx;
    if (!write || write->policy_id != PICOKEYS_VAULT_POLICY_ID || write->key_domain != 0 || write->object_tag > UINT8_MAX) {
        return false;
    }
    if (write->object_type == PICOKEYS_VAULT_OBJECT_WRAP) {
        return write->data.len == PICOKEYS_VAULT_WRAP_SIZE && write->protection == PICOKEYS_VAULT_WRAP_PROTECTION && write->flags == PICOKEYS_VAULT_WRAP_FLAGS;
    }
    return write->object_type == PICOKEYS_VAULT_OBJECT_LABEL && write->object_tag == 0 && write->data.len <= PICOKEYS_VAULT_LABEL_MAX && write->protection == PICOKEYS_VAULT_LABEL_PROTECTION && write->flags == PICOKEYS_VAULT_LABEL_FLAGS;
}

static bool vault_descriptor_valid(void *ctx, uint32_t container_id, const file_object_descriptor_t *object) {
    (void)ctx;
    return container_id == PICOKEYS_VAULT_CONTAINER_ID && object && vault_object_type_valid(object->object_type) && object->object_tag <= UINT8_MAX && (object->object_type == PICOKEYS_VAULT_OBJECT_WRAP || object->object_tag == 0) && object->policy_id == PICOKEYS_VAULT_POLICY_ID && object->key_domain == 0;
}

static int vault_marker_write(void) {
    static const uint8_t marker[] = { 'P', 'K', 'V', 'O', 1 };
    if (!vault_state.legacy_file) {
        return PICOKEYS_OK;
    }
    int ret = flash_clear_file(vault_state.legacy_file);
    if (ret != PICOKEYS_OK) {
        return ret;
    }
    return file_put_data(vault_state.legacy_file, CONST_BYTE_ARRAY(marker, sizeof(marker)));
}

static int vault_layout_activate(void *ctx, uint32_t container_id) {
    (void)ctx;
    return container_id == PICOKEYS_VAULT_CONTAINER_ID ? vault_marker_write() : PICOKEYS_WRONG_DATA;
}

static int vault_layout_retire(void *ctx, uint32_t container_id, const file_object_container_state_t *state, const file_object_manifest_t *next, uint8_t current_slot, uint8_t target_slot) {
    (void)ctx;
    (void)current_slot;
    if (container_id != PICOKEYS_VAULT_CONTAINER_ID || !state || !next) {
        return PICOKEYS_WRONG_DATA;
    }
    for (uint8_t slot = 0; slot < FILE_OBJECT_CONTAINER_SLOT_COUNT; slot++) {
        const file_object_container_candidate_t *candidate = &state->candidates[slot];
        if (!candidate->valid) {
            continue;
        }
        for (uint16_t i = 0; i < candidate->manifest.object_count; i++) {
            const file_object_descriptor_t *object = &candidate->manifest.objects[i];
            if (!file_object_container_references(next, object->record_id)) {
                uint16_t record_fid = 0;
                if (vault_layout_record_fid(ctx, container_id, object, &record_fid) != PICOKEYS_OK) {
                    return PICOKEYS_WRONG_DATA;
                }
                file_t *record = file_search(record_fid);
                if (record) {
                    file_delete_no_commit(record);
                }
            }
        }
        if (slot != target_slot) {
            file_t *manifest = file_search(vault_manifest_fid(slot));
            if (manifest) {
                file_delete_no_commit(manifest);
            }
        }
    }
    return PICOKEYS_OK;
}

static int vault_layout_deactivate(void *ctx, uint32_t container_id) {
    (void)ctx;
    if (container_id != PICOKEYS_VAULT_CONTAINER_ID || !vault_state.legacy_file) {
        return PICOKEYS_OK;
    }
    return flash_clear_file(vault_state.legacy_file);
}

static const file_object_container_layout_t vault_layout = {
    .ctx = &vault_state,
    .namespace_id = PICOKEYS_VAULT_NAMESPACE,
    .container_kind = PICOKEYS_VAULT_CONTAINER_KIND,
    .manifest_fid = vault_layout_manifest_fid,
    .record_fid = vault_layout_record_fid,
    .record_allocate = vault_layout_record_allocate,
    .policy_hash = vault_policy_hash,
    .write_valid = vault_write_valid,
    .descriptor_valid = vault_descriptor_valid,
    .activate = vault_layout_activate,
    .deactivate = vault_layout_deactivate,
    .retire = vault_layout_retire,
    .rollback_new_records = true
};

int picokeys_vault_init(const file_object_container_crypto_t *primary, const file_object_container_crypto_t *legacy, file_t *legacy_file, file_t *legacy_label_file) {
    if (!primary || !primary->auth || !primary->protector) {
        log_errstr("vault container init: invalid primary crypto primary=%p auth=%p protector=%p", (void *)primary, primary ? (void *)primary->auth : NULL, primary ? (void *)primary->protector : NULL);
        return PICOKEYS_ERR_NULL_PARAM;
    }
    vault_state.layout = &vault_layout;
    vault_state.primary = *primary;
    vault_state.has_legacy = legacy && legacy->auth && legacy->protector;
    vault_state.legacy = vault_state.has_legacy ? *legacy : (file_object_container_crypto_t){ 0 };
    vault_state.legacy_file = legacy_file;
    vault_state.legacy_label_file = legacy_label_file;
    vault_state.initialized = true;
    return PICOKEYS_OK;
}

static int vault_update(const file_object_container_write_t *writes, size_t write_count) {
    if (!vault_state_valid() || !writes || write_count == 0) {
        log_errstr("vault container update: invalid arguments initialized=%d writes=%p write_count=%zu", vault_state_valid(), (void *)writes, write_count);
        return PICOKEYS_ERR_NULL_PARAM;
    }
    int ret = file_object_container_update_without_record_validation(vault_state.layout, PICOKEYS_VAULT_CONTAINER_ID, writes, write_count, &vault_state.primary, vault_state.has_legacy ? &vault_state.legacy : NULL);
    if (ret != PICOKEYS_OK) {
        log_errstr("vault container update: object update failed ret=%d write_count=%zu", ret, write_count);
    }
    return ret;
}

bool picokeys_vault_wrap_available(uint8_t app_id) {
    uint32_t object_size = 0;
    return vault_state_valid() && file_object_container_object_size(vault_state.layout, PICOKEYS_VAULT_CONTAINER_ID, PICOKEYS_VAULT_OBJECT_WRAP, app_id, &vault_state.primary, vault_state.has_legacy ? &vault_state.legacy : NULL, NULL, NULL, &object_size) == PICOKEYS_OK && object_size == PICOKEYS_VAULT_WRAP_SIZE;
}

static int vault_get_wrap_record(uint8_t app_id, uint8_t record[PICOKEYS_VAULT_RECORD_SIZE]) {
    if (!vault_state_valid() || !record) {
        log_errstr("vault container read wrap: invalid arguments initialized=%d record=%p app_id=%u", vault_state_valid(), (void *)record, app_id);
        return PICOKEYS_ERR_NULL_PARAM;
    }
    byte_buffer_t output = BYTE_BUFFER(record, PICOKEYS_VAULT_RECORD_SIZE);
    int ret = file_object_container_read(vault_state.layout, PICOKEYS_VAULT_CONTAINER_ID, PICOKEYS_VAULT_OBJECT_WRAP, app_id, &vault_state.primary, vault_state.has_legacy ? &vault_state.legacy : NULL, NULL, NULL, &output);
    if (ret == PICOKEYS_OK && output.len != PICOKEYS_VAULT_RECORD_SIZE) {
        log_errstr("vault container read wrap: invalid record length actual=%zu expected=%u app_id=%u", output.len, PICOKEYS_VAULT_RECORD_SIZE, app_id);
        return PICOKEYS_WRONG_LENGTH;
    }
    if (ret != PICOKEYS_OK && ret != PICOKEYS_ERR_FILE_NOT_FOUND) {
        log_errstr("vault container read wrap: object read failed ret=%d app_id=%u", ret, app_id);
    }
    return ret;
}

static int vault_set_wrap_record(const uint8_t record[PICOKEYS_VAULT_RECORD_SIZE], uint8_t app_id) {
    if (!record) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    const file_object_container_write_t write = {
        .object_type = PICOKEYS_VAULT_OBJECT_WRAP,
        .object_tag = app_id,
        .data = CONST_BYTE_ARRAY(record, PICOKEYS_VAULT_RECORD_SIZE),
        .policy_id = PICOKEYS_VAULT_POLICY_ID,
        .key_domain = 0,
        .protection = PICOKEYS_VAULT_WRAP_PROTECTION,
        .flags = PICOKEYS_VAULT_WRAP_FLAGS
    };
    return vault_update(&write, 1);
}

static int vault_migrate_legacy(void);

int picokeys_vault_set_kvault(const uint8_t kvault[PICOKEYS_VAULT_KEY_SIZE], const uint8_t encryption_key[PICOKEYS_VAULT_KEY_SIZE], uint8_t app_id) {
    if (!kvault || !encryption_key) {
        log_errstr("vault container set key: invalid arguments kvault=%p encryption_key=%p app_id=%u", (void *)kvault, (void *)encryption_key, app_id);
        return PICOKEYS_ERR_NULL_PARAM;
    }
    uint8_t record[PICOKEYS_VAULT_RECORD_SIZE] = { 0 };
    int ret = vault_wrap(encryption_key, kvault, record);
    if (ret == PICOKEYS_OK) {
        ret = vault_set_wrap_record(record, app_id);
    }
    mbedtls_platform_zeroize(record, sizeof(record));
    return ret;
}

int picokeys_vault_get_kvault(uint8_t app_id, const uint8_t encryption_key[PICOKEYS_VAULT_KEY_SIZE], uint8_t kvault[PICOKEYS_VAULT_KEY_SIZE]) {
    if (!encryption_key || !kvault) {
        log_errstr("vault container get key: invalid arguments encryption_key=%p kvault=%p app_id=%u", (void *)encryption_key, (void *)kvault, app_id);
        return PICOKEYS_ERR_NULL_PARAM;
    }
    uint8_t record[PICOKEYS_VAULT_RECORD_SIZE] = { 0 };
    int ret = vault_get_wrap_record(app_id, record);
    if (ret == PICOKEYS_ERR_FILE_NOT_FOUND && app_id == 0 && vault_state.legacy_file) {
        ret = vault_migrate_legacy();
        if (ret == PICOKEYS_OK) {
            ret = vault_get_wrap_record(0, record);
        }
    }
    if (ret == PICOKEYS_OK) {
        ret = vault_unwrap(encryption_key, record, kvault);
    }
    if (ret == PICOKEYS_ERR_FILE_NOT_FOUND) {
        log_errstr("vault container get key: record unavailable app_id=%u", app_id);
    }
    mbedtls_platform_zeroize(record, sizeof(record));
    return ret;
}

int picokeys_vault_get_label(byte_buffer_t *label) {
    if (!vault_state_valid() || !label || label->len > label->capacity || (!label->data && label->capacity > 0)) {
        log_errstr("vault container get label: invalid arguments initialized=%d label=%p", vault_state_valid(), (void *)label);
        return PICOKEYS_ERR_NULL_PARAM;
    }
    int ret = file_object_container_read(vault_state.layout, PICOKEYS_VAULT_CONTAINER_ID, PICOKEYS_VAULT_OBJECT_LABEL, 0, &vault_state.primary, vault_state.has_legacy ? &vault_state.legacy : NULL, NULL, NULL, label);
    if (ret != PICOKEYS_OK && ret != PICOKEYS_ERR_FILE_NOT_FOUND) {
        log_errstr("vault container get label: object read failed ret=%d capacity=%zu", ret, label->capacity);
    }
    return ret == PICOKEYS_ERR_FILE_NOT_FOUND ? PICOKEYS_OK : ret;
}

int picokeys_vault_set_label(const_byte_array_t label) {
    if (label.len > PICOKEYS_VAULT_LABEL_MAX || (!label.data && label.len > 0)) {
        log_errstr("vault container set label: invalid arguments data=%p length=%zu max=%u", (void *)label.data, label.len, PICOKEYS_VAULT_LABEL_MAX);
        return label.len > PICOKEYS_VAULT_LABEL_MAX ? PICOKEYS_WRONG_LENGTH : PICOKEYS_ERR_NULL_PARAM;
    }
    const file_object_container_write_t write = {
        .object_type = PICOKEYS_VAULT_OBJECT_LABEL,
        .object_tag = 0,
        .data = label,
        .policy_id = PICOKEYS_VAULT_POLICY_ID,
        .key_domain = 0,
        .protection = PICOKEYS_VAULT_LABEL_PROTECTION,
        .flags = PICOKEYS_VAULT_LABEL_FLAGS
    };
    return vault_update(&write, 1);
}

static int vault_clear_file(file_t *file) {
    if (!file) {
        return PICOKEYS_OK;
    }
    meta_delete_no_commit(file->fid);
    return flash_clear_file(file);
}

static int vault_migrate_legacy(void) {
    if (!vault_state_valid() || !vault_state.legacy_file) {
        log_errstr("vault legacy migration: invalid state initialized=%d legacy_file=%p", vault_state_valid(), (void *)vault_state.legacy_file);
        return PICOKEYS_ERR_NULL_PARAM;
    }
    uint8_t record[PICOKEYS_VAULT_RECORD_SIZE] = { 0 };
    int ret = vault_get_wrap_record(0, record);
    if (ret != PICOKEYS_ERR_FILE_NOT_FOUND) {
        if (ret != PICOKEYS_OK) {
            log_errstr("vault legacy migration: new container read failed ret=%d", ret);
        }
        mbedtls_platform_zeroize(record, sizeof(record));
        return ret;
    }
    const uint8_t *legacy_record = vault_legacy_record(vault_state.legacy_file);
    if (!legacy_record) {
        log_errstr("vault legacy migration: legacy record unavailable file=%p", (void *)vault_state.legacy_file);
        mbedtls_platform_zeroize(record, sizeof(record));
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    memcpy(record, legacy_record, sizeof(record));

    uint8_t label[PICOKEYS_VAULT_ENROLL_PLAIN_MAX] = { 0 };
    size_t label_len = 0;
    if (vault_state.legacy_label_file && file_has_data(vault_state.legacy_label_file)) {
        label_len = file_get_size(vault_state.legacy_label_file);
        if (label_len > PICOKEYS_VAULT_LABEL_MAX || label_len > sizeof(label)) {
            log_errstr("vault legacy migration: label too long length=%zu max=%u", label_len, PICOKEYS_VAULT_LABEL_MAX);
            mbedtls_platform_zeroize(label, sizeof(label));
            mbedtls_platform_zeroize(record, sizeof(record));
            return PICOKEYS_WRONG_LENGTH;
        }
        memcpy(label, file_get_data(vault_state.legacy_label_file), label_len);
    }
    const file_object_container_write_t writes[] = {
        {
            .object_type = PICOKEYS_VAULT_OBJECT_WRAP,
            .object_tag = 0,
            .data = CONST_BYTE_ARRAY(record, sizeof(record)),
            .policy_id = PICOKEYS_VAULT_POLICY_ID,
            .key_domain = 0,
            .protection = PICOKEYS_VAULT_WRAP_PROTECTION,
            .flags = PICOKEYS_VAULT_WRAP_FLAGS
        },
        {
            .object_type = PICOKEYS_VAULT_OBJECT_LABEL,
            .object_tag = 0,
            .data = CONST_BYTE_ARRAY(label, label_len),
            .policy_id = PICOKEYS_VAULT_POLICY_ID,
            .key_domain = 0,
            .protection = PICOKEYS_VAULT_LABEL_PROTECTION,
            .flags = PICOKEYS_VAULT_LABEL_FLAGS
        }
    };
    ret = vault_update(writes, sizeof(writes) / sizeof(writes[0]));
    if (ret == PICOKEYS_OK && vault_state.legacy_label_file) {
        ret = vault_clear_file(vault_state.legacy_label_file);
        if (ret == PICOKEYS_OK) {
            flash_commit();
        }
        else {
            log_errstr("vault legacy migration: label cleanup failed ret=%d", ret);
        }
    }
    mbedtls_platform_zeroize(label, sizeof(label));
    mbedtls_platform_zeroize(record, sizeof(record));
    return ret;
}

int picokeys_vault_delete_kvault(uint8_t app_id) {
    if (!vault_state_valid()) {
        log_errstr("vault container delete: invalid state initialized=%d app_id=%u", vault_state_valid(), app_id);
        return PICOKEYS_ERR_NULL_PARAM;
    }
    file_object_container_state_t state;
    int ret = file_object_container_load(vault_state.layout, PICOKEYS_VAULT_CONTAINER_ID, &vault_state.primary, vault_state.has_legacy ? &vault_state.legacy : NULL, &state);
    if (ret == PICOKEYS_ERR_FILE_NOT_FOUND) {
        if (app_id == 0 && vault_state.legacy_file && vault_legacy_record(vault_state.legacy_file)) {
            ret = vault_clear_legacy_record(vault_state.legacy_file);
        }
        else {
            ret = PICOKEYS_OK;
        }
        if (ret == PICOKEYS_OK && app_id == 0 && vault_state.legacy_label_file) {
            ret = vault_clear_file(vault_state.legacy_label_file);
            if (ret == PICOKEYS_OK) {
                flash_commit();
            }
            else {
                log_errstr("vault container delete: legacy label cleanup failed ret=%d", ret);
            }
        }
        return ret;
    }
    if (ret != PICOKEYS_OK) {
        log_errstr("vault container delete: container load failed ret=%d app_id=%u", ret, app_id);
        return ret;
    }
    file_object_container_candidate_t *current = &state.candidates[state.current_slot];
    ret = file_object_container_validate(vault_state.layout, PICOKEYS_VAULT_CONTAINER_ID, current, state.crypto.protector);
    if (ret != PICOKEYS_OK) {
        file_object_container_candidate_t *previous = &state.candidates[current->slot ^ 1u];
        if (!previous->valid || file_object_container_validate(vault_state.layout, PICOKEYS_VAULT_CONTAINER_ID, previous, state.crypto.protector) != PICOKEYS_OK) {
            log_errstr("vault container delete: current and previous container validation failed current_slot=%u", current->slot);
            return ret;
        }
        current = previous;
    }
    const file_object_descriptor_t *wrap = file_object_container_find(&current->manifest, PICOKEYS_VAULT_OBJECT_WRAP, app_id);
    if (!wrap) {
        log_errstr("vault container delete: wrap record missing app_id=%u", app_id);
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    uint16_t wrap_count = 0;
    for (uint16_t i = 0; i < current->manifest.object_count; i++) {
        if (current->manifest.objects[i].object_type == PICOKEYS_VAULT_OBJECT_WRAP) {
            wrap_count++;
        }
    }
    if (wrap_count == 1) {
        ret = file_object_container_delete(vault_state.layout, PICOKEYS_VAULT_CONTAINER_ID, &vault_state.primary, vault_state.has_legacy ? &vault_state.legacy : NULL);
    }
    else {
        ret = file_object_container_remove(vault_state.layout, PICOKEYS_VAULT_CONTAINER_ID, PICOKEYS_VAULT_OBJECT_WRAP, app_id, &vault_state.primary, vault_state.has_legacy ? &vault_state.legacy : NULL);
    }
    if (ret != PICOKEYS_OK) {
        log_errstr("vault container delete: object deletion failed ret=%d app_id=%u wrap_count=%u", ret, app_id, wrap_count);
    }
    return ret;
}
