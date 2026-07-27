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

#ifndef _OBJECT_CONTAINER_STORE_H_
#define _OBJECT_CONTAINER_STORE_H_

#include "object_container.h"

#define FILE_OBJECT_CONTAINER_SLOT_COUNT 2u
#define FILE_OBJECT_CONTAINER_INVALID_SLOT UINT8_MAX

typedef struct file_object_container_write {
    uint16_t object_type;
    uint16_t object_tag;
    const_byte_array_t data;
    uint16_t policy_id;
    uint8_t key_domain;
    uint8_t protection;
    uint16_t flags;
    uint16_t transaction_group;
} file_object_container_write_t;

typedef struct file_object_container_candidate {
    file_object_manifest_t manifest;
    uint8_t slot;
    bool valid;
} file_object_container_candidate_t;

typedef struct file_object_container_crypto {
    const file_object_authenticator_t *auth;
    const file_object_record_protector_t *protector;
} file_object_container_crypto_t;

typedef struct file_object_container_state {
    file_object_container_candidate_t candidates[FILE_OBJECT_CONTAINER_SLOT_COUNT];
    file_object_container_crypto_t crypto;
    uint8_t current_slot;
} file_object_container_state_t;

typedef uint16_t (*file_object_container_manifest_fid_t)(void *ctx, uint32_t container_id, uint8_t slot);
typedef int (*file_object_container_record_fid_t)(void *ctx, uint32_t container_id, const file_object_descriptor_t *object, uint16_t *fid);
typedef int (*file_object_container_record_allocate_t)(void *ctx, uint32_t container_id, uint8_t target_slot, const file_object_container_write_t *write, const file_object_authenticator_t *auth, uint64_t *record_id, uint16_t *fid);
typedef int (*file_object_container_policy_hash_t)(void *ctx, uint16_t policy_id, uint8_t hash[FILE_OBJECT_POLICY_HASH_SIZE]);
typedef bool (*file_object_container_write_valid_t)(void *ctx, const file_object_container_write_t *write);
typedef bool (*file_object_container_descriptor_valid_t)(void *ctx, uint32_t container_id, const file_object_descriptor_t *object);
typedef int (*file_object_container_activate_t)(void *ctx, uint32_t container_id);
typedef int (*file_object_container_deactivate_t)(void *ctx, uint32_t container_id);
typedef int (*file_object_container_retire_t)(void *ctx, uint32_t container_id, const file_object_container_state_t *state, const file_object_manifest_t *next, uint8_t current_slot, uint8_t target_slot);
typedef int (*file_object_container_access_t)(void *ctx, const file_object_descriptor_t *object);

typedef struct file_object_container_layout {
    void *ctx;
    uint16_t namespace_id;
    uint16_t container_kind;
    uint32_t commit_timeout_ms;
    file_object_container_manifest_fid_t manifest_fid;
    file_object_container_record_fid_t record_fid;
    file_object_container_record_allocate_t record_allocate;
    file_object_container_policy_hash_t policy_hash;
    file_object_container_write_valid_t write_valid;
    file_object_container_descriptor_valid_t descriptor_valid;
    file_object_container_activate_t activate;
    file_object_container_deactivate_t deactivate;
    file_object_container_retire_t retire;
    bool rollback_new_records;
} file_object_container_layout_t;

int file_object_container_load(const file_object_container_layout_t *layout, uint32_t container_id, const file_object_container_crypto_t *primary, const file_object_container_crypto_t *legacy, file_object_container_state_t *state);
int file_object_container_validate(const file_object_container_layout_t *layout, uint32_t container_id, const file_object_container_candidate_t *candidate, const file_object_record_protector_t *protector);
const file_object_descriptor_t *file_object_container_find(const file_object_manifest_t *manifest, uint16_t object_type, uint16_t object_tag);
bool file_object_container_references(const file_object_manifest_t *manifest, uint64_t record_id);
int file_object_container_object_size(const file_object_container_layout_t *layout, uint32_t container_id, uint16_t object_type, uint16_t object_tag, const file_object_container_crypto_t *primary, const file_object_container_crypto_t *legacy, file_object_container_access_t access, void *access_ctx, uint32_t *object_size);
int file_object_container_read(const file_object_container_layout_t *layout, uint32_t container_id, uint16_t object_type, uint16_t object_tag, const file_object_container_crypto_t *primary, const file_object_container_crypto_t *legacy, file_object_container_access_t access, void *access_ctx, byte_buffer_t *data);
int file_object_container_update(const file_object_container_layout_t *layout, uint32_t container_id, const file_object_container_write_t *writes, size_t write_count, const file_object_container_crypto_t *primary, const file_object_container_crypto_t *legacy);
int file_object_container_remove(const file_object_container_layout_t *layout, uint32_t container_id, uint16_t object_type, uint16_t object_tag, const file_object_container_crypto_t *primary, const file_object_container_crypto_t *legacy);
int file_object_container_delete(const file_object_container_layout_t *layout, uint32_t container_id, const file_object_container_crypto_t *primary, const file_object_container_crypto_t *legacy);

#endif // _OBJECT_CONTAINER_STORE_H_
