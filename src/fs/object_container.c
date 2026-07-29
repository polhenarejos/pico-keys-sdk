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
#include "object_container.h"

#define FILE_OBJECT_MANIFEST_FLAGS_OFFSET 6u
#define FILE_OBJECT_MANIFEST_NAMESPACE_OFFSET 8u
#define FILE_OBJECT_MANIFEST_KIND_OFFSET 10u
#define FILE_OBJECT_MANIFEST_CONTAINER_ID_OFFSET 12u
#define FILE_OBJECT_MANIFEST_GENERATION_OFFSET 16u
#define FILE_OBJECT_MANIFEST_PREVIOUS_GENERATION_OFFSET 20u
#define FILE_OBJECT_MANIFEST_OBJECT_COUNT_OFFSET 24u
#define FILE_OBJECT_MANIFEST_DESCRIPTOR_SIZE_OFFSET 26u
#define FILE_OBJECT_MANIFEST_RESERVED_OFFSET 27u
#define FILE_OBJECT_MANIFEST_EXTENSION_SIZE_OFFSET 28u
#define FILE_OBJECT_MANIFEST_TOTAL_SIZE_OFFSET 30u

#define FILE_OBJECT_DESCRIPTOR_TYPE_OFFSET 0u
#define FILE_OBJECT_DESCRIPTOR_TAG_OFFSET 2u
#define FILE_OBJECT_DESCRIPTOR_GENERATION_OFFSET 4u
#define FILE_OBJECT_DESCRIPTOR_LOGICAL_SIZE_OFFSET 8u
#define FILE_OBJECT_DESCRIPTOR_RECORD_ID_OFFSET 12u
#define FILE_OBJECT_DESCRIPTOR_STORED_SIZE_OFFSET 20u
#define FILE_OBJECT_DESCRIPTOR_POLICY_ID_OFFSET 24u
#define FILE_OBJECT_DESCRIPTOR_KEY_DOMAIN_OFFSET 26u
#define FILE_OBJECT_DESCRIPTOR_PROTECTION_OFFSET 27u
#define FILE_OBJECT_DESCRIPTOR_FLAGS_OFFSET 28u
#define FILE_OBJECT_DESCRIPTOR_EXTENSION_OFFSET 30u
#define FILE_OBJECT_DESCRIPTOR_EXTENSION_SIZE_OFFSET 32u
#define FILE_OBJECT_DESCRIPTOR_TRANSACTION_GROUP_OFFSET 34u

#define FILE_OBJECT_RECORD_PROTECTION_OFFSET 5u
#define FILE_OBJECT_RECORD_HEADER_SIZE_OFFSET 6u
#define FILE_OBJECT_RECORD_ID_OFFSET 8u
#define FILE_OBJECT_RECORD_STORED_SIZE_OFFSET 16u
#define FILE_OBJECT_RECORD_LOGICAL_SIZE_OFFSET 20u
#define FILE_OBJECT_RECORD_GENERATION_OFFSET 24u
#define FILE_OBJECT_RECORD_NONCE_OFFSET 28u

#define FILE_OBJECT_RECORD_AAD_NAMESPACE_OFFSET 5u
#define FILE_OBJECT_RECORD_AAD_KIND_OFFSET 7u
#define FILE_OBJECT_RECORD_AAD_CONTAINER_ID_OFFSET 9u
#define FILE_OBJECT_RECORD_AAD_TYPE_OFFSET 13u
#define FILE_OBJECT_RECORD_AAD_TAG_OFFSET 15u
#define FILE_OBJECT_RECORD_AAD_GENERATION_OFFSET 17u
#define FILE_OBJECT_RECORD_AAD_LOGICAL_SIZE_OFFSET 21u
#define FILE_OBJECT_RECORD_AAD_POLICY_ID_OFFSET 25u
#define FILE_OBJECT_RECORD_AAD_POLICY_HASH_OFFSET 27u
#define FILE_OBJECT_RECORD_AAD_KEY_DOMAIN_OFFSET 43u
#define FILE_OBJECT_RECORD_AAD_PROTECTION_OFFSET 44u
#define FILE_OBJECT_RECORD_AAD_FLAGS_OFFSET 45u
#define FILE_OBJECT_RECORD_AAD_RECORD_ID_OFFSET 47u

#define FILE_OBJECT_RECORD_ID_STATE_SIZE 16u
#define FILE_OBJECT_RECORD_ID_FORMAT_VERSION 1u
#define FILE_OBJECT_RECORD_ID_VERSION_OFFSET 4u
#define FILE_OBJECT_RECORD_ID_VALUE_OFFSET 8u

static const uint8_t file_object_manifest_magic[4] = { 'P', 'K', 'O', 'C' };
static const uint8_t file_object_record_magic[4] = { 'P', 'K', 'O', 'R' };
static const uint8_t file_object_record_id_magic[4] = { 'P', 'K', 'R', 'I' };

static bool file_object_manifest_auth_valid(const file_object_authenticator_t *auth) {
    return auth && auth->start && auth->update && auth->finish;
}

static bool file_object_record_protector_valid(const file_object_record_protector_t *protector) {
    return protector && protector->seal && protector->unseal;
}

static void file_object_manifest_auth_abort(const file_object_authenticator_t *auth) {
    if (auth && auth->abort) {
        auth->abort(auth->ctx);
    }
}

static int file_object_manifest_authenticate(const file_object_authenticator_t *auth, const_byte_array_t data, uint8_t tag[FILE_OBJECT_AUTH_TAG_SIZE]) {
    int r = auth->start(auth->ctx);
    if (r != PICOKEYS_OK) {
        file_object_manifest_auth_abort(auth);
        return r;
    }
    r = auth->update(auth->ctx, data);
    if (r == PICOKEYS_OK) {
        r = auth->finish(auth->ctx, tag);
    }
    if (r != PICOKEYS_OK) {
        file_object_manifest_auth_abort(auth);
    }
    return r;
}

static bool file_object_manifest_tag_equal(const uint8_t *left, const uint8_t *right) {
    uint8_t difference = 0;
    for (size_t i = 0; i < FILE_OBJECT_AUTH_TAG_SIZE; i++) {
        difference |= left[i] ^ right[i];
    }
    return difference == 0;
}

static bool file_object_descriptor_core_valid(const file_object_descriptor_t *object) {
    if (!object || object->object_type == 0 || object->object_type == UINT16_MAX || object->generation == 0 || object->record_id == 0) {
        return false;
    }
    if (object->protection < FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC || object->protection > FILE_OBJECT_PROTECTION_FIRMWARE_INTERNAL || (object->flags & ~FILE_OBJECT_FLAG_MASK) != 0 || (object->flags & FILE_OBJECT_FLAG_INLINE) != 0) {
        return false;
    }
    bool grouped = (object->flags & FILE_OBJECT_FLAG_TRANSACTION_GROUP) != 0;
    if (grouped != (object->transaction_group != 0)) {
        return false;
    }
    if ((object->extension_offset == 0) != (object->extension_size == 0)) {
        return false;
    }
    return true;
}

static bool file_object_descriptor_valid(const file_object_descriptor_t *object, uint16_t extension_start, uint16_t extension_end) {
    if (!file_object_descriptor_core_valid(object)) {
        return false;
    }
    if (object->extension_size > 0 && (object->extension_offset < extension_start || object->extension_offset > extension_end || object->extension_size > extension_end - object->extension_offset)) {
        return false;
    }
    return true;
}

static bool file_object_descriptors_valid(const file_object_descriptor_t *objects, uint16_t object_count, uint16_t extension_start, uint16_t extension_end) {
    for (uint16_t i = 0; i < object_count; i++) {
        if (!file_object_descriptor_valid(&objects[i], extension_start, extension_end)) {
            return false;
        }
        if (i > 0 && (objects[i - 1].object_type > objects[i].object_type || (objects[i - 1].object_type == objects[i].object_type && objects[i - 1].object_tag >= objects[i].object_tag))) {
            return false;
        }
    }
    return true;
}

static int file_object_extensions_validate(const_byte_array_t extensions, file_object_extension_supported_t extension_supported, void *extension_ctx) {
    uint32_t offset = 0;
    while (offset < extensions.len) {
        if (extensions.len - offset < FILE_OBJECT_EXTENSION_HEADER_SIZE) {
            return PICOKEYS_WRONG_DATA;
        }
        uint8_t kind = extensions.data[offset];
        uint8_t flags = extensions.data[offset + 1];
        uint16_t value_size = get_uint16_be(extensions.data + offset + 2);
        if (kind == 0 || (flags & ~FILE_OBJECT_EXTENSION_FLAG_CRITICAL) != 0 || value_size > extensions.len - offset - FILE_OBJECT_EXTENSION_HEADER_SIZE) {
            return PICOKEYS_WRONG_DATA;
        }
        bool supported = extension_supported && extension_supported(extension_ctx, kind);
        if ((flags & FILE_OBJECT_EXTENSION_FLAG_CRITICAL) != 0 && !supported) {
            return PICOKEYS_WRONG_DATA;
        }
        offset += FILE_OBJECT_EXTENSION_HEADER_SIZE + value_size;
    }
    return offset == extensions.len ? PICOKEYS_OK : PICOKEYS_WRONG_DATA;
}

static bool file_object_extension_accept_all(void *ctx, uint8_t kind) {
    (void)ctx;
    (void)kind;
    return true;
}

static void file_object_descriptor_encode(const file_object_descriptor_t *object, uint8_t data[FILE_OBJECT_DESCRIPTOR_SIZE]) {
    put_uint16_be(object->object_type, data + FILE_OBJECT_DESCRIPTOR_TYPE_OFFSET);
    put_uint16_be(object->object_tag, data + FILE_OBJECT_DESCRIPTOR_TAG_OFFSET);
    put_uint32_be(object->generation, data + FILE_OBJECT_DESCRIPTOR_GENERATION_OFFSET);
    put_uint32_be(object->logical_size, data + FILE_OBJECT_DESCRIPTOR_LOGICAL_SIZE_OFFSET);
    put_uint64_be(object->record_id, data + FILE_OBJECT_DESCRIPTOR_RECORD_ID_OFFSET);
    put_uint32_be(object->stored_size, data + FILE_OBJECT_DESCRIPTOR_STORED_SIZE_OFFSET);
    put_uint16_be(object->policy_id, data + FILE_OBJECT_DESCRIPTOR_POLICY_ID_OFFSET);
    data[FILE_OBJECT_DESCRIPTOR_KEY_DOMAIN_OFFSET] = object->key_domain;
    data[FILE_OBJECT_DESCRIPTOR_PROTECTION_OFFSET] = object->protection;
    put_uint16_be(object->flags, data + FILE_OBJECT_DESCRIPTOR_FLAGS_OFFSET);
    put_uint16_be(object->extension_offset, data + FILE_OBJECT_DESCRIPTOR_EXTENSION_OFFSET);
    put_uint16_be(object->extension_size, data + FILE_OBJECT_DESCRIPTOR_EXTENSION_SIZE_OFFSET);
    put_uint16_be(object->transaction_group, data + FILE_OBJECT_DESCRIPTOR_TRANSACTION_GROUP_OFFSET);
}

static void file_object_descriptor_decode(const uint8_t data[FILE_OBJECT_DESCRIPTOR_SIZE], file_object_descriptor_t *object) {
    *object = (file_object_descriptor_t) {
        .object_type = get_uint16_be(data + FILE_OBJECT_DESCRIPTOR_TYPE_OFFSET),
        .object_tag = get_uint16_be(data + FILE_OBJECT_DESCRIPTOR_TAG_OFFSET),
        .generation = get_uint32_be(data + FILE_OBJECT_DESCRIPTOR_GENERATION_OFFSET),
        .logical_size = get_uint32_be(data + FILE_OBJECT_DESCRIPTOR_LOGICAL_SIZE_OFFSET),
        .record_id = get_uint64_be(data + FILE_OBJECT_DESCRIPTOR_RECORD_ID_OFFSET),
        .stored_size = get_uint32_be(data + FILE_OBJECT_DESCRIPTOR_STORED_SIZE_OFFSET),
        .policy_id = get_uint16_be(data + FILE_OBJECT_DESCRIPTOR_POLICY_ID_OFFSET),
        .key_domain = data[FILE_OBJECT_DESCRIPTOR_KEY_DOMAIN_OFFSET],
        .protection = data[FILE_OBJECT_DESCRIPTOR_PROTECTION_OFFSET],
        .flags = get_uint16_be(data + FILE_OBJECT_DESCRIPTOR_FLAGS_OFFSET),
        .extension_offset = get_uint16_be(data + FILE_OBJECT_DESCRIPTOR_EXTENSION_OFFSET),
        .extension_size = get_uint16_be(data + FILE_OBJECT_DESCRIPTOR_EXTENSION_SIZE_OFFSET),
        .transaction_group = get_uint16_be(data + FILE_OBJECT_DESCRIPTOR_TRANSACTION_GROUP_OFFSET)
    };
}

int file_object_manifest_build(const file_object_manifest_t *manifest, const_byte_array_t extensions, const file_object_authenticator_t *auth, byte_buffer_t *output) {
    if (!manifest || (!extensions.data && extensions.len > 0) || extensions.len > UINT16_MAX || !file_object_manifest_auth_valid(auth) || !output || output->len > output->capacity || !output->data) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    uint16_t extensions_size = (uint16_t)extensions.len;
    const uint8_t *extension_data = extensions.data;
    uint8_t *data = output->data + output->len;

    uint16_t object_count = manifest->object_count;
    if (object_count == 0 && manifest->has_object) {
        object_count = 1;
    }
    if (object_count > FILE_OBJECT_MANIFEST_MAX_OBJECTS) {
        return PICOKEYS_WRONG_DATA;
    }
    uint32_t descriptor_bytes = (uint32_t)object_count * FILE_OBJECT_DESCRIPTOR_SIZE;
    uint32_t total_size = FILE_OBJECT_MANIFEST_HEADER_SIZE + descriptor_bytes + extensions_size + FILE_OBJECT_AUTH_TAG_SIZE;
    if (manifest->generation == 0 || manifest->previous_generation >= manifest->generation) {
        return PICOKEYS_WRONG_DATA;
    }
    if (total_size > UINT16_MAX || output->capacity - output->len < total_size) {
        return PICOKEYS_WRONG_LENGTH;
    }
    uint16_t extension_start = (uint16_t)(FILE_OBJECT_MANIFEST_HEADER_SIZE + descriptor_bytes);
    uint16_t extension_end = (uint16_t)(extension_start + extensions_size);
    if (!file_object_descriptors_valid(manifest->objects, object_count, extension_start, extension_end)) {
        return PICOKEYS_WRONG_DATA;
    }
    int r = file_object_extensions_validate(CONST_BYTE_ARRAY(extension_data, extensions_size), file_object_extension_accept_all, NULL);
    if (r != PICOKEYS_OK) {
        return r;
    }
    for (uint16_t i = 0; i < object_count; i++) {
        if (manifest->objects[i].extension_size > 0) {
            r = file_object_extensions_validate(CONST_BYTE_ARRAY(extension_data + manifest->objects[i].extension_offset - extension_start, manifest->objects[i].extension_size), file_object_extension_accept_all, NULL);
            if (r != PICOKEYS_OK) {
                return r;
            }
        }
    }

    memset(data, 0, total_size);
    memcpy(data, file_object_manifest_magic, sizeof(file_object_manifest_magic));
    data[4] = FILE_OBJECT_MANIFEST_FORMAT_VERSION;
    data[5] = FILE_OBJECT_MANIFEST_HEADER_SIZE;
    put_uint16_be(manifest->flags, data + FILE_OBJECT_MANIFEST_FLAGS_OFFSET);
    put_uint16_be(manifest->namespace_id, data + FILE_OBJECT_MANIFEST_NAMESPACE_OFFSET);
    put_uint16_be(manifest->container_kind, data + FILE_OBJECT_MANIFEST_KIND_OFFSET);
    put_uint32_be(manifest->container_id, data + FILE_OBJECT_MANIFEST_CONTAINER_ID_OFFSET);
    put_uint32_be(manifest->generation, data + FILE_OBJECT_MANIFEST_GENERATION_OFFSET);
    put_uint32_be(manifest->previous_generation, data + FILE_OBJECT_MANIFEST_PREVIOUS_GENERATION_OFFSET);
    put_uint16_be(object_count, data + FILE_OBJECT_MANIFEST_OBJECT_COUNT_OFFSET);
    data[FILE_OBJECT_MANIFEST_DESCRIPTOR_SIZE_OFFSET] = FILE_OBJECT_DESCRIPTOR_SIZE;
    put_uint16_be(extensions_size, data + FILE_OBJECT_MANIFEST_EXTENSION_SIZE_OFFSET);
    put_uint16_be((uint16_t)total_size, data + FILE_OBJECT_MANIFEST_TOTAL_SIZE_OFFSET);
    for (uint16_t i = 0; i < object_count; i++) {
        file_object_descriptor_encode(&manifest->objects[i], data + FILE_OBJECT_MANIFEST_HEADER_SIZE + (size_t)i * FILE_OBJECT_DESCRIPTOR_SIZE);
    }
    if (extensions_size > 0) {
        memcpy(data + extension_start, extension_data, extensions_size);
    }
    r = file_object_manifest_authenticate(auth, CONST_BYTE_ARRAY(data, total_size - FILE_OBJECT_AUTH_TAG_SIZE), data + total_size - FILE_OBJECT_AUTH_TAG_SIZE);
    if (r != PICOKEYS_OK) {
        memset(data, 0, total_size);
        return r;
    }
    output->len += total_size;
    return PICOKEYS_OK;
}

int file_object_manifest_parse(const_byte_array_t data, const file_object_authenticator_t *auth, file_object_extension_supported_t extension_supported, void *extension_ctx, file_object_manifest_t *manifest) {
    if (!data.data || !file_object_manifest_auth_valid(auth) || !manifest) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    if (data.len < FILE_OBJECT_MANIFEST_HEADER_SIZE + FILE_OBJECT_AUTH_TAG_SIZE || data.len > UINT16_MAX) {
        return PICOKEYS_WRONG_LENGTH;
    }

    uint16_t object_count = get_uint16_be(data.data + FILE_OBJECT_MANIFEST_OBJECT_COUNT_OFFSET);
    uint16_t extensions_size = get_uint16_be(data.data + FILE_OBJECT_MANIFEST_EXTENSION_SIZE_OFFSET);
    uint16_t total_size = get_uint16_be(data.data + FILE_OBJECT_MANIFEST_TOTAL_SIZE_OFFSET);
    if (memcmp(data.data, file_object_manifest_magic, sizeof(file_object_manifest_magic)) != 0 || data.data[4] != FILE_OBJECT_MANIFEST_FORMAT_VERSION || data.data[5] != FILE_OBJECT_MANIFEST_HEADER_SIZE || object_count > FILE_OBJECT_MANIFEST_MAX_OBJECTS || data.data[FILE_OBJECT_MANIFEST_DESCRIPTOR_SIZE_OFFSET] != FILE_OBJECT_DESCRIPTOR_SIZE || data.data[FILE_OBJECT_MANIFEST_RESERVED_OFFSET] != 0 || total_size != data.len) {
        return PICOKEYS_WRONG_DATA;
    }
    uint32_t descriptor_bytes = object_count * FILE_OBJECT_DESCRIPTOR_SIZE;
    uint32_t expected_size = FILE_OBJECT_MANIFEST_HEADER_SIZE + descriptor_bytes + extensions_size + FILE_OBJECT_AUTH_TAG_SIZE;
    if (expected_size != data.len) {
        return PICOKEYS_WRONG_DATA;
    }

    uint8_t calculated_tag[FILE_OBJECT_AUTH_TAG_SIZE];
    int r = file_object_manifest_authenticate(auth, CONST_BYTE_ARRAY(data.data, data.len - FILE_OBJECT_AUTH_TAG_SIZE), calculated_tag);
    if (r == PICOKEYS_OK && !file_object_manifest_tag_equal(calculated_tag, data.data + data.len - FILE_OBJECT_AUTH_TAG_SIZE)) {
        r = PICOKEYS_WRONG_SIGNATURE;
    }
    memset(calculated_tag, 0, sizeof(calculated_tag));
    if (r != PICOKEYS_OK) {
        return r;
    }

    uint16_t extension_start = (uint16_t)(FILE_OBJECT_MANIFEST_HEADER_SIZE + descriptor_bytes);
    uint16_t extension_end = (uint16_t)(extension_start + extensions_size);
    r = file_object_extensions_validate(CONST_BYTE_ARRAY(data.data + extension_start, extensions_size), extension_supported, extension_ctx);
    if (r != PICOKEYS_OK) {
        return r;
    }

    file_object_manifest_t parsed = {
        .flags = get_uint16_be(data.data + FILE_OBJECT_MANIFEST_FLAGS_OFFSET),
        .namespace_id = get_uint16_be(data.data + FILE_OBJECT_MANIFEST_NAMESPACE_OFFSET),
        .container_kind = get_uint16_be(data.data + FILE_OBJECT_MANIFEST_KIND_OFFSET),
        .container_id = get_uint32_be(data.data + FILE_OBJECT_MANIFEST_CONTAINER_ID_OFFSET),
        .generation = get_uint32_be(data.data + FILE_OBJECT_MANIFEST_GENERATION_OFFSET),
        .previous_generation = get_uint32_be(data.data + FILE_OBJECT_MANIFEST_PREVIOUS_GENERATION_OFFSET),
        .extension_offset = extension_start,
        .extension_size = extensions_size,
        .total_size = total_size,
        .object_count = object_count,
        .has_object = object_count > 0
    };
    if (parsed.generation == 0 || parsed.previous_generation >= parsed.generation) {
        return PICOKEYS_WRONG_DATA;
    }
    for (uint16_t i = 0; i < object_count; i++) {
        file_object_descriptor_decode(data.data + FILE_OBJECT_MANIFEST_HEADER_SIZE + (size_t)i * FILE_OBJECT_DESCRIPTOR_SIZE, &parsed.objects[i]);
    }
    if (!file_object_descriptors_valid(parsed.objects, object_count, extension_start, extension_end)) {
        return PICOKEYS_WRONG_DATA;
    }
    for (uint16_t i = 0; i < object_count; i++) {
        if (parsed.objects[i].extension_size > 0) {
            r = file_object_extensions_validate(CONST_BYTE_ARRAY(data.data + parsed.objects[i].extension_offset, parsed.objects[i].extension_size), extension_supported, extension_ctx);
            if (r != PICOKEYS_OK) {
                return r;
            }
        }
    }
    *manifest = parsed;
    return PICOKEYS_OK;
}

int file_object_record_header_build(const file_object_descriptor_t *object, uint8_t header[FILE_OBJECT_RECORD_HEADER_SIZE]) {
    if (!object || !header) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    if (!file_object_descriptor_core_valid(object)) {
        return PICOKEYS_WRONG_DATA;
    }

    memset(header, 0, FILE_OBJECT_RECORD_HEADER_SIZE);
    memcpy(header, file_object_record_magic, sizeof(file_object_record_magic));
    header[4] = FILE_OBJECT_RECORD_FORMAT_VERSION;
    header[FILE_OBJECT_RECORD_PROTECTION_OFFSET] = object->protection;
    put_uint16_be(FILE_OBJECT_RECORD_HEADER_SIZE, header + FILE_OBJECT_RECORD_HEADER_SIZE_OFFSET);
    put_uint64_be(object->record_id, header + FILE_OBJECT_RECORD_ID_OFFSET);
    put_uint32_be(object->stored_size, header + FILE_OBJECT_RECORD_STORED_SIZE_OFFSET);
    put_uint32_be(object->logical_size, header + FILE_OBJECT_RECORD_LOGICAL_SIZE_OFFSET);
    put_uint32_be(object->generation, header + FILE_OBJECT_RECORD_GENERATION_OFFSET);
    put_uint64_be(object->record_id, header + FILE_OBJECT_RECORD_NONCE_OFFSET);
    put_uint32_be(object->generation, header + FILE_OBJECT_RECORD_NONCE_OFFSET + sizeof(uint64_t));
    return PICOKEYS_OK;
}

int file_object_record_header_parse(const_byte_array_t record, const file_object_descriptor_t *object, file_object_record_info_t *info) {
    if (!record.data || !object || !info) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    if (!file_object_descriptor_core_valid(object)) {
        return PICOKEYS_WRONG_DATA;
    }
    uint64_t expected_size = (uint64_t)FILE_OBJECT_RECORD_HEADER_SIZE + object->stored_size + FILE_OBJECT_AUTH_TAG_SIZE;
    if (record.len < FILE_OBJECT_RECORD_HEADER_SIZE + FILE_OBJECT_AUTH_TAG_SIZE || expected_size > SIZE_MAX || record.len != (size_t)expected_size) {
        return PICOKEYS_WRONG_LENGTH;
    }
    uint64_t record_id = get_uint64_be(record.data + FILE_OBJECT_RECORD_ID_OFFSET);
    uint32_t stored_size = get_uint32_be(record.data + FILE_OBJECT_RECORD_STORED_SIZE_OFFSET);
    uint32_t logical_size = get_uint32_be(record.data + FILE_OBJECT_RECORD_LOGICAL_SIZE_OFFSET);
    uint32_t generation = get_uint32_be(record.data + FILE_OBJECT_RECORD_GENERATION_OFFSET);
    uint64_t nonce_record_id = get_uint64_be(record.data + FILE_OBJECT_RECORD_NONCE_OFFSET);
    uint32_t nonce_generation = get_uint32_be(record.data + FILE_OBJECT_RECORD_NONCE_OFFSET + sizeof(uint64_t));
    if (memcmp(record.data, file_object_record_magic, sizeof(file_object_record_magic)) != 0
        || record.data[4] != FILE_OBJECT_RECORD_FORMAT_VERSION
        || record.data[FILE_OBJECT_RECORD_PROTECTION_OFFSET] != object->protection
        || get_uint16_be(record.data + FILE_OBJECT_RECORD_HEADER_SIZE_OFFSET) != FILE_OBJECT_RECORD_HEADER_SIZE
        || record_id != object->record_id
        || stored_size != object->stored_size
        || logical_size != object->logical_size
        || generation != object->generation
        || nonce_record_id != record_id
        || nonce_generation != generation) {
        return PICOKEYS_WRONG_DATA;
    }
    *info = (file_object_record_info_t) {
        .record_id = record_id,
        .stored_size = stored_size,
        .logical_size = logical_size,
        .generation = generation,
        .protection = record.data[FILE_OBJECT_RECORD_PROTECTION_OFFSET],
        .payload_offset = FILE_OBJECT_RECORD_HEADER_SIZE,
        .tag_offset = FILE_OBJECT_RECORD_HEADER_SIZE + stored_size
    };
    return PICOKEYS_OK;
}

static int file_object_record_identity_build(const file_object_manifest_t *manifest, const uint8_t policy_hash[FILE_OBJECT_POLICY_HASH_SIZE], file_object_record_identity_t *identity, uint8_t aad[FILE_OBJECT_RECORD_AAD_SIZE]) {
    if (!manifest || !manifest->has_object || !policy_hash || !identity || !aad || !file_object_descriptor_core_valid(&manifest->object)) {
        return PICOKEYS_WRONG_DATA;
    }

    const file_object_descriptor_t *object = &manifest->object;
    *identity = (file_object_record_identity_t) {
        .namespace_id = manifest->namespace_id,
        .container_kind = manifest->container_kind,
        .container_id = manifest->container_id,
        .object_type = object->object_type,
        .object_tag = object->object_tag,
        .generation = object->generation,
        .logical_size = object->logical_size,
        .policy_id = object->policy_id,
        .key_domain = object->key_domain,
        .protection = object->protection,
        .flags = object->flags,
        .record_id = object->record_id
    };
    memcpy(identity->policy_hash, policy_hash, FILE_OBJECT_POLICY_HASH_SIZE);

    memset(aad, 0, FILE_OBJECT_RECORD_AAD_SIZE);
    memcpy(aad, file_object_record_magic, sizeof(file_object_record_magic));
    aad[4] = FILE_OBJECT_RECORD_FORMAT_VERSION;
    put_uint16_be(identity->namespace_id, aad + FILE_OBJECT_RECORD_AAD_NAMESPACE_OFFSET);
    put_uint16_be(identity->container_kind, aad + FILE_OBJECT_RECORD_AAD_KIND_OFFSET);
    put_uint32_be(identity->container_id, aad + FILE_OBJECT_RECORD_AAD_CONTAINER_ID_OFFSET);
    put_uint16_be(identity->object_type, aad + FILE_OBJECT_RECORD_AAD_TYPE_OFFSET);
    put_uint16_be(identity->object_tag, aad + FILE_OBJECT_RECORD_AAD_TAG_OFFSET);
    put_uint32_be(identity->generation, aad + FILE_OBJECT_RECORD_AAD_GENERATION_OFFSET);
    put_uint32_be(identity->logical_size, aad + FILE_OBJECT_RECORD_AAD_LOGICAL_SIZE_OFFSET);
    put_uint16_be(identity->policy_id, aad + FILE_OBJECT_RECORD_AAD_POLICY_ID_OFFSET);
    memcpy(aad + FILE_OBJECT_RECORD_AAD_POLICY_HASH_OFFSET, identity->policy_hash, FILE_OBJECT_POLICY_HASH_SIZE);
    aad[FILE_OBJECT_RECORD_AAD_KEY_DOMAIN_OFFSET] = identity->key_domain;
    aad[FILE_OBJECT_RECORD_AAD_PROTECTION_OFFSET] = identity->protection;
    put_uint16_be(identity->flags, aad + FILE_OBJECT_RECORD_AAD_FLAGS_OFFSET);
    put_uint64_be(identity->record_id, aad + FILE_OBJECT_RECORD_AAD_RECORD_ID_OFFSET);
    return PICOKEYS_OK;
}

int file_object_record_seal(const file_object_manifest_t *manifest, const uint8_t policy_hash[FILE_OBJECT_POLICY_HASH_SIZE], const file_object_record_protector_t *protector, const_byte_array_t plaintext, byte_buffer_t *record) {
    if (!manifest || !policy_hash || !file_object_record_protector_valid(protector) || (!plaintext.data && plaintext.len > 0) || !record || record->len > record->capacity || (!record->data && record->capacity > 0)) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    if (!manifest->has_object || plaintext.len != manifest->object.logical_size || plaintext.len != manifest->object.stored_size) {
        return PICOKEYS_WRONG_LENGTH;
    }
    uint64_t required_size = (uint64_t)FILE_OBJECT_RECORD_HEADER_SIZE + plaintext.len + FILE_OBJECT_AUTH_TAG_SIZE;
    if (required_size > SIZE_MAX || record->capacity - record->len < (size_t)required_size) {
        return PICOKEYS_WRONG_LENGTH;
    }
    uint8_t *record_data = record->data + record->len;

    file_object_record_identity_t identity;
    uint8_t aad[FILE_OBJECT_RECORD_AAD_SIZE];
    int r = file_object_record_identity_build(manifest, policy_hash, &identity, aad);
    if (r == PICOKEYS_OK) {
        r = file_object_record_header_build(&manifest->object, record_data);
    }
    if (r == PICOKEYS_OK) {
        byte_buffer_t stored = BYTE_BUFFER(record_data + FILE_OBJECT_RECORD_HEADER_SIZE, plaintext.len);
        r = protector->seal(protector->ctx, &identity, record_data + FILE_OBJECT_RECORD_NONCE_OFFSET, aad, plaintext, &stored, record_data + FILE_OBJECT_RECORD_HEADER_SIZE + plaintext.len);
        if (r == PICOKEYS_OK && stored.len != plaintext.len) {
            r = PICOKEYS_WRONG_LENGTH;
        }
    }
    memset(&identity, 0, sizeof(identity));
    memset(aad, 0, sizeof(aad));
    if (r != PICOKEYS_OK) {
        memset(record_data, 0, (size_t)required_size);
        return r;
    }
    record->len += (size_t)required_size;
    return PICOKEYS_OK;
}

int file_object_record_unseal(const file_object_manifest_t *manifest, const uint8_t policy_hash[FILE_OBJECT_POLICY_HASH_SIZE], const file_object_record_protector_t *protector, const_byte_array_t record, byte_buffer_t *plaintext) {
    if (!manifest || !policy_hash || !file_object_record_protector_valid(protector) || !record.data || !plaintext || plaintext->len > plaintext->capacity || (!plaintext->data && plaintext->capacity > 0)) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    if (!manifest->has_object || plaintext->capacity - plaintext->len < manifest->object.logical_size || manifest->object.logical_size != manifest->object.stored_size) {
        return PICOKEYS_WRONG_LENGTH;
    }

    file_object_record_info_t info;
    int r = file_object_record_header_parse(record, &manifest->object, &info);
    file_object_record_identity_t identity;
    uint8_t aad[FILE_OBJECT_RECORD_AAD_SIZE];
    if (r == PICOKEYS_OK) {
        r = file_object_record_identity_build(manifest, policy_hash, &identity, aad);
    }
    if (r == PICOKEYS_OK) {
        byte_buffer_t output = BYTE_BUFFER(plaintext->data ? plaintext->data + plaintext->len : NULL, plaintext->capacity - plaintext->len);
        r = protector->unseal(protector->ctx, &identity, record.data + FILE_OBJECT_RECORD_NONCE_OFFSET, aad, CONST_BYTE_ARRAY(record.data + info.payload_offset, info.stored_size), record.data + info.tag_offset, &output);
        if (r == PICOKEYS_OK && output.len != info.logical_size) {
            r = PICOKEYS_WRONG_LENGTH;
        }
    }
    memset(&identity, 0, sizeof(identity));
    memset(aad, 0, sizeof(aad));
    if (r != PICOKEYS_OK) {
        if (plaintext->data && plaintext->capacity > plaintext->len) {
            memset(plaintext->data + plaintext->len, 0, MIN(plaintext->capacity - plaintext->len, manifest->object.logical_size));
        }
        return r;
    }
    plaintext->len += info.logical_size;
    return PICOKEYS_OK;
}

int file_object_record_id_allocate(const file_object_txn_layout_t *layout, const file_object_authenticator_t *auth, uint64_t *record_id) {
    if (!layout || !auth || !record_id) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    *record_id = 0;

    uint64_t next_id = 1;
    file_object_txn_handle_t handle = FILE_OBJECT_TXN_INVALID_HANDLE;
    int r = file_object_txn_open(layout, auth, &handle);
    if (r == PICOKEYS_OK) {
        file_object_info_t info;
        uint8_t state[FILE_OBJECT_RECORD_ID_STATE_SIZE];
        r = file_object_txn_get_info(handle, auth, &info);
        if (r == PICOKEYS_OK && info.payload_size != sizeof(state)) {
            r = PICOKEYS_WRONG_DATA;
        }
        if (r == PICOKEYS_OK) {
            r = file_object_txn_read_at(handle, auth, 0, BYTE_ARRAY(state, sizeof(state)));
        }
        if (r == PICOKEYS_OK && (memcmp(state, file_object_record_id_magic, sizeof(file_object_record_id_magic)) != 0 || state[FILE_OBJECT_RECORD_ID_VERSION_OFFSET] != FILE_OBJECT_RECORD_ID_FORMAT_VERSION || state[5] != 0 || state[6] != 0 || state[7] != 0)) {
            r = PICOKEYS_WRONG_DATA;
        }
        if (r == PICOKEYS_OK) {
            uint64_t previous_id = get_uint64_be(state + FILE_OBJECT_RECORD_ID_VALUE_OFFSET);
            if (previous_id == 0 || previous_id == UINT64_MAX) {
                r = PICOKEYS_WRONG_DATA;
            }
            else {
                next_id = previous_id + 1;
            }
        }
        memset(state, 0, sizeof(state));
        int close_result = file_object_txn_close(handle);
        if (r == PICOKEYS_OK) {
            r = close_result;
        }
    }
    else if (r == PICOKEYS_ERR_FILE_NOT_FOUND) {
        r = PICOKEYS_OK;
    }
    if (r != PICOKEYS_OK) {
        return r;
    }

    uint8_t state[FILE_OBJECT_RECORD_ID_STATE_SIZE] = { 0 };
    memcpy(state, file_object_record_id_magic, sizeof(file_object_record_id_magic));
    state[FILE_OBJECT_RECORD_ID_VERSION_OFFSET] = FILE_OBJECT_RECORD_ID_FORMAT_VERSION;
    put_uint64_be(next_id, state + FILE_OBJECT_RECORD_ID_VALUE_OFFSET);
    r = file_object_txn_put(layout, auth, CONST_BYTE_ARRAY(state, sizeof(state)));
    if (r == PICOKEYS_OK) {
        /* Return an ID only after both recovery slots contain the high-water mark. */
        r = file_object_txn_put(layout, auth, CONST_BYTE_ARRAY(state, sizeof(state)));
    }
    memset(state, 0, sizeof(state));
    if (r != PICOKEYS_OK) {
        return r;
    }
    *record_id = next_id;
    return PICOKEYS_OK;
}
