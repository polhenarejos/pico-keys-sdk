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

static const uint8_t file_object_manifest_magic[4] = { 'P', 'K', 'O', 'C' };
static const uint8_t file_object_record_magic[4] = { 'P', 'K', 'O', 'R' };

static bool file_object_manifest_auth_valid(const file_object_authenticator_t *auth) {
    return auth && auth->start && auth->update && auth->finish;
}

static void file_object_manifest_auth_abort(const file_object_authenticator_t *auth) {
    if (auth && auth->abort) {
        auth->abort(auth->ctx);
    }
}

static int file_object_manifest_authenticate(const file_object_authenticator_t *auth, const uint8_t *data, size_t len, uint8_t tag[FILE_OBJECT_AUTH_TAG_SIZE]) {
    int r = auth->start(auth->ctx);
    if (r != PICOKEYS_OK) {
        file_object_manifest_auth_abort(auth);
        return r;
    }
    r = auth->update(auth->ctx, data, len);
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

static int file_object_extensions_validate(const uint8_t *extensions, uint16_t extensions_size, file_object_extension_supported_t extension_supported, void *extension_ctx) {
    uint32_t offset = 0;
    while (offset < extensions_size) {
        if (extensions_size - offset < FILE_OBJECT_EXTENSION_HEADER_SIZE) {
            return PICOKEYS_WRONG_DATA;
        }
        uint8_t kind = extensions[offset];
        uint8_t flags = extensions[offset + 1];
        uint16_t value_size = get_uint16_be(extensions + offset + 2);
        if (kind == 0 || (flags & ~FILE_OBJECT_EXTENSION_FLAG_CRITICAL) != 0 || value_size > extensions_size - offset - FILE_OBJECT_EXTENSION_HEADER_SIZE) {
            return PICOKEYS_WRONG_DATA;
        }
        bool supported = extension_supported && extension_supported(extension_ctx, kind);
        if ((flags & FILE_OBJECT_EXTENSION_FLAG_CRITICAL) != 0 && !supported) {
            return PICOKEYS_WRONG_DATA;
        }
        offset += FILE_OBJECT_EXTENSION_HEADER_SIZE + value_size;
    }
    return offset == extensions_size ? PICOKEYS_OK : PICOKEYS_WRONG_DATA;
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

int file_object_manifest_build(const file_object_manifest_t *manifest, const uint8_t *extensions, uint16_t extensions_size, const file_object_authenticator_t *auth, uint8_t *data, size_t capacity, size_t *written) {
    if (!manifest || (!extensions && extensions_size > 0) || !file_object_manifest_auth_valid(auth) || !data || !written) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    *written = 0;

    uint32_t descriptor_bytes = manifest->has_object ? FILE_OBJECT_DESCRIPTOR_SIZE : 0;
    uint32_t total_size = FILE_OBJECT_MANIFEST_HEADER_SIZE + descriptor_bytes + extensions_size + FILE_OBJECT_AUTH_TAG_SIZE;
    uint16_t extension_start = FILE_OBJECT_MANIFEST_HEADER_SIZE + descriptor_bytes;
    uint16_t extension_end = extension_start + extensions_size;
    if (manifest->generation == 0 || manifest->previous_generation >= manifest->generation) {
        return PICOKEYS_WRONG_DATA;
    }
    if (total_size > UINT16_MAX || capacity < total_size) {
        return PICOKEYS_WRONG_LENGTH;
    }
    if (manifest->has_object && !file_object_descriptor_valid(&manifest->object, extension_start, extension_end)) {
        return PICOKEYS_WRONG_DATA;
    }
    int r = file_object_extensions_validate(extensions, extensions_size, file_object_extension_accept_all, NULL);
    if (r != PICOKEYS_OK) {
        return r;
    }
    if (manifest->has_object && manifest->object.extension_size > 0) {
        r = file_object_extensions_validate(extensions + manifest->object.extension_offset - extension_start, manifest->object.extension_size, file_object_extension_accept_all, NULL);
        if (r != PICOKEYS_OK) {
            return r;
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
    put_uint16_be(manifest->has_object ? 1u : 0u, data + FILE_OBJECT_MANIFEST_OBJECT_COUNT_OFFSET);
    data[FILE_OBJECT_MANIFEST_DESCRIPTOR_SIZE_OFFSET] = FILE_OBJECT_DESCRIPTOR_SIZE;
    put_uint16_be(extensions_size, data + FILE_OBJECT_MANIFEST_EXTENSION_SIZE_OFFSET);
    put_uint16_be((uint16_t)total_size, data + FILE_OBJECT_MANIFEST_TOTAL_SIZE_OFFSET);
    if (manifest->has_object) {
        file_object_descriptor_encode(&manifest->object, data + FILE_OBJECT_MANIFEST_HEADER_SIZE);
    }
    if (extensions_size > 0) {
        memcpy(data + extension_start, extensions, extensions_size);
    }
    r = file_object_manifest_authenticate(auth, data, total_size - FILE_OBJECT_AUTH_TAG_SIZE, data + total_size - FILE_OBJECT_AUTH_TAG_SIZE);
    if (r != PICOKEYS_OK) {
        memset(data, 0, total_size);
        return r;
    }
    *written = total_size;
    return PICOKEYS_OK;
}

int file_object_manifest_parse(const uint8_t *data, size_t len, const file_object_authenticator_t *auth, file_object_extension_supported_t extension_supported, void *extension_ctx, file_object_manifest_t *manifest) {
    if (!data || !file_object_manifest_auth_valid(auth) || !manifest) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    if (len < FILE_OBJECT_MANIFEST_HEADER_SIZE + FILE_OBJECT_AUTH_TAG_SIZE || len > UINT16_MAX) {
        return PICOKEYS_WRONG_LENGTH;
    }

    uint16_t object_count = get_uint16_be(data + FILE_OBJECT_MANIFEST_OBJECT_COUNT_OFFSET);
    uint16_t extensions_size = get_uint16_be(data + FILE_OBJECT_MANIFEST_EXTENSION_SIZE_OFFSET);
    uint16_t total_size = get_uint16_be(data + FILE_OBJECT_MANIFEST_TOTAL_SIZE_OFFSET);
    if (memcmp(data, file_object_manifest_magic, sizeof(file_object_manifest_magic)) != 0 || data[4] != FILE_OBJECT_MANIFEST_FORMAT_VERSION || data[5] != FILE_OBJECT_MANIFEST_HEADER_SIZE || object_count > FILE_OBJECT_MANIFEST_MAX_OBJECTS || data[FILE_OBJECT_MANIFEST_DESCRIPTOR_SIZE_OFFSET] != FILE_OBJECT_DESCRIPTOR_SIZE || data[FILE_OBJECT_MANIFEST_RESERVED_OFFSET] != 0 || total_size != len) {
        return PICOKEYS_WRONG_DATA;
    }
    uint32_t descriptor_bytes = object_count * FILE_OBJECT_DESCRIPTOR_SIZE;
    uint32_t expected_size = FILE_OBJECT_MANIFEST_HEADER_SIZE + descriptor_bytes + extensions_size + FILE_OBJECT_AUTH_TAG_SIZE;
    if (expected_size != len) {
        return PICOKEYS_WRONG_DATA;
    }

    uint8_t calculated_tag[FILE_OBJECT_AUTH_TAG_SIZE];
    int r = file_object_manifest_authenticate(auth, data, len - FILE_OBJECT_AUTH_TAG_SIZE, calculated_tag);
    if (r == PICOKEYS_OK && !file_object_manifest_tag_equal(calculated_tag, data + len - FILE_OBJECT_AUTH_TAG_SIZE)) {
        r = PICOKEYS_WRONG_SIGNATURE;
    }
    memset(calculated_tag, 0, sizeof(calculated_tag));
    if (r != PICOKEYS_OK) {
        return r;
    }

    uint16_t extension_start = FILE_OBJECT_MANIFEST_HEADER_SIZE + descriptor_bytes;
    uint16_t extension_end = extension_start + extensions_size;
    r = file_object_extensions_validate(data + extension_start, extensions_size, extension_supported, extension_ctx);
    if (r != PICOKEYS_OK) {
        return r;
    }

    file_object_manifest_t parsed = {
        .flags = get_uint16_be(data + FILE_OBJECT_MANIFEST_FLAGS_OFFSET),
        .namespace_id = get_uint16_be(data + FILE_OBJECT_MANIFEST_NAMESPACE_OFFSET),
        .container_kind = get_uint16_be(data + FILE_OBJECT_MANIFEST_KIND_OFFSET),
        .container_id = get_uint32_be(data + FILE_OBJECT_MANIFEST_CONTAINER_ID_OFFSET),
        .generation = get_uint32_be(data + FILE_OBJECT_MANIFEST_GENERATION_OFFSET),
        .previous_generation = get_uint32_be(data + FILE_OBJECT_MANIFEST_PREVIOUS_GENERATION_OFFSET),
        .extension_offset = extension_start,
        .extension_size = extensions_size,
        .total_size = total_size,
        .has_object = object_count == 1
    };
    if (parsed.generation == 0 || parsed.previous_generation >= parsed.generation) {
        return PICOKEYS_WRONG_DATA;
    }
    if (parsed.has_object) {
        file_object_descriptor_decode(data + FILE_OBJECT_MANIFEST_HEADER_SIZE, &parsed.object);
        if (!file_object_descriptor_valid(&parsed.object, extension_start, extension_end)) {
            return PICOKEYS_WRONG_DATA;
        }
        if (parsed.object.extension_size > 0) {
            r = file_object_extensions_validate(data + parsed.object.extension_offset, parsed.object.extension_size, extension_supported, extension_ctx);
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

int file_object_record_header_parse(const uint8_t *record, size_t len, const file_object_descriptor_t *object, file_object_record_info_t *info) {
    if (!record || !object || !info) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    if (!file_object_descriptor_core_valid(object)) {
        return PICOKEYS_WRONG_DATA;
    }
    uint64_t expected_size = (uint64_t)FILE_OBJECT_RECORD_HEADER_SIZE + object->stored_size + FILE_OBJECT_AUTH_TAG_SIZE;
    if (len < FILE_OBJECT_RECORD_HEADER_SIZE + FILE_OBJECT_AUTH_TAG_SIZE || expected_size > SIZE_MAX || len != (size_t)expected_size) {
        return PICOKEYS_WRONG_LENGTH;
    }
    uint64_t record_id = get_uint64_be(record + FILE_OBJECT_RECORD_ID_OFFSET);
    uint32_t stored_size = get_uint32_be(record + FILE_OBJECT_RECORD_STORED_SIZE_OFFSET);
    uint32_t logical_size = get_uint32_be(record + FILE_OBJECT_RECORD_LOGICAL_SIZE_OFFSET);
    uint32_t generation = get_uint32_be(record + FILE_OBJECT_RECORD_GENERATION_OFFSET);
    uint64_t nonce_record_id = get_uint64_be(record + FILE_OBJECT_RECORD_NONCE_OFFSET);
    uint32_t nonce_generation = get_uint32_be(record + FILE_OBJECT_RECORD_NONCE_OFFSET + sizeof(uint64_t));
    if (memcmp(record, file_object_record_magic, sizeof(file_object_record_magic)) != 0 || record[4] != FILE_OBJECT_RECORD_FORMAT_VERSION || record[FILE_OBJECT_RECORD_PROTECTION_OFFSET] != object->protection || get_uint16_be(record + FILE_OBJECT_RECORD_HEADER_SIZE_OFFSET) != FILE_OBJECT_RECORD_HEADER_SIZE || record_id != object->record_id || stored_size != object->stored_size || logical_size != object->logical_size || generation != object->generation || nonce_record_id != record_id || nonce_generation != generation) {
        return PICOKEYS_WRONG_DATA;
    }
    *info = (file_object_record_info_t) { .record_id = record_id, .stored_size = stored_size, .logical_size = logical_size, .generation = generation, .protection = record[FILE_OBJECT_RECORD_PROTECTION_OFFSET], .payload_offset = FILE_OBJECT_RECORD_HEADER_SIZE, .tag_offset = FILE_OBJECT_RECORD_HEADER_SIZE + stored_size };
    return PICOKEYS_OK;
}
