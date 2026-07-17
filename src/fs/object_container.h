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

#ifndef _OBJECT_CONTAINER_H_
#define _OBJECT_CONTAINER_H_

#include "object_store.h"

#define FILE_OBJECT_MANIFEST_FORMAT_VERSION 1u
#define FILE_OBJECT_MANIFEST_HEADER_SIZE 32u
#define FILE_OBJECT_DESCRIPTOR_SIZE 36u
#define FILE_OBJECT_MANIFEST_MAX_OBJECTS 8u
#define FILE_OBJECT_EXTENSION_HEADER_SIZE 4u
#define FILE_OBJECT_EXTENSION_FLAG_CRITICAL 0x01u

#define FILE_OBJECT_RECORD_FORMAT_VERSION 1u
#define FILE_OBJECT_RECORD_HEADER_SIZE 40u
#define FILE_OBJECT_RECORD_NONCE_SIZE 12u
#define FILE_OBJECT_RECORD_AAD_SIZE 55u
#define FILE_OBJECT_POLICY_HASH_SIZE 16u

#define FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC 1u
#define FILE_OBJECT_PROTECTION_AEAD_SECRET 2u
#define FILE_OBJECT_PROTECTION_FIRMWARE_INTERNAL 3u

#define FILE_OBJECT_FLAG_INLINE 0x0001u
#define FILE_OBJECT_FLAG_MUTABLE 0x0002u
#define FILE_OBJECT_FLAG_NON_EXPORTABLE 0x0004u
#define FILE_OBJECT_FLAG_GENERIC_READABLE 0x0008u
#define FILE_OBJECT_FLAG_TRANSACTION_GROUP 0x0010u
#define FILE_OBJECT_FLAG_MONOTONIC 0x0020u
#define FILE_OBJECT_FLAG_MASK 0x003fu

typedef struct file_object_descriptor {
    uint16_t object_type;
    uint16_t object_tag;
    uint32_t generation;
    uint32_t logical_size;
    uint64_t record_id;
    uint32_t stored_size;
    uint16_t policy_id;
    uint8_t key_domain;
    uint8_t protection;
    uint16_t flags;
    uint16_t extension_offset;
    uint16_t extension_size;
    uint16_t transaction_group;
} file_object_descriptor_t;

typedef struct file_object_manifest {
    uint16_t flags;
    uint16_t namespace_id;
    uint16_t container_kind;
    uint32_t container_id;
    uint32_t generation;
    uint32_t previous_generation;
    uint16_t extension_offset;
    uint16_t extension_size;
    uint16_t total_size;
    uint16_t object_count;
    bool has_object;
    union {
        file_object_descriptor_t object;
        file_object_descriptor_t objects[FILE_OBJECT_MANIFEST_MAX_OBJECTS];
    };
} file_object_manifest_t;

typedef struct file_object_record_info {
    uint64_t record_id;
    uint32_t stored_size;
    uint32_t logical_size;
    uint32_t generation;
    uint8_t protection;
    uint32_t payload_offset;
    uint32_t tag_offset;
} file_object_record_info_t;

typedef struct file_object_record_identity {
    uint16_t namespace_id;
    uint16_t container_kind;
    uint32_t container_id;
    uint16_t object_type;
    uint16_t object_tag;
    uint32_t generation;
    uint32_t logical_size;
    uint16_t policy_id;
    uint8_t policy_hash[FILE_OBJECT_POLICY_HASH_SIZE];
    uint8_t key_domain;
    uint8_t protection;
    uint16_t flags;
    uint64_t record_id;
} file_object_record_identity_t;

/* Providers must cryptographically bind the supplied AAD, nonce and stored bytes. */
typedef struct file_object_record_protector {
    void *ctx;
    int (*seal)(void *ctx, const file_object_record_identity_t *identity, const uint8_t nonce[FILE_OBJECT_RECORD_NONCE_SIZE], const uint8_t aad[FILE_OBJECT_RECORD_AAD_SIZE], const uint8_t *plaintext, size_t len, uint8_t *stored, uint8_t tag[FILE_OBJECT_AUTH_TAG_SIZE]);
    int (*unseal)(void *ctx, const file_object_record_identity_t *identity, const uint8_t nonce[FILE_OBJECT_RECORD_NONCE_SIZE], const uint8_t aad[FILE_OBJECT_RECORD_AAD_SIZE], const uint8_t *stored, size_t len, const uint8_t tag[FILE_OBJECT_AUTH_TAG_SIZE], uint8_t *plaintext);
} file_object_record_protector_t;

typedef bool (*file_object_extension_supported_t)(void *ctx, uint8_t kind);

int file_object_manifest_build(const file_object_manifest_t *manifest, const uint8_t *extensions, uint16_t extensions_size, const file_object_authenticator_t *auth, uint8_t *data, size_t capacity, size_t *written);
int file_object_manifest_parse(const uint8_t *data, size_t len, const file_object_authenticator_t *auth, file_object_extension_supported_t extension_supported, void *extension_ctx, file_object_manifest_t *manifest);

/* This validates record framing and descriptor binding, not the record authentication tag. */
int file_object_record_header_build(const file_object_descriptor_t *object, uint8_t header[FILE_OBJECT_RECORD_HEADER_SIZE]);
int file_object_record_header_parse(const uint8_t *record, size_t len, const file_object_descriptor_t *object, file_object_record_info_t *info);
int file_object_record_seal(const file_object_manifest_t *manifest, const uint8_t policy_hash[FILE_OBJECT_POLICY_HASH_SIZE], const file_object_record_protector_t *protector, const uint8_t *plaintext, uint32_t plaintext_size, uint8_t *record, size_t capacity, size_t *written);
int file_object_record_unseal(const file_object_manifest_t *manifest, const uint8_t policy_hash[FILE_OBJECT_POLICY_HASH_SIZE], const file_object_record_protector_t *protector, const uint8_t *record, size_t record_size, uint8_t *plaintext, size_t capacity, size_t *written);

int file_object_record_id_allocate(const file_object_txn_layout_t *layout, const file_object_authenticator_t *auth, uint64_t *record_id);

#endif // _OBJECT_CONTAINER_H_
