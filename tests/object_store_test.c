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
#include "fs/object_container.h"
#include "fs/object_store.h"

#include <assert.h>
#include <stdio.h>

#define TEST_FILE_COUNT 4u
#define TEST_FILE_CAPACITY 256u
#define TEST_TXN_RECORD_HEADER_SIZE 32u
#define TEST_TXN_COMMIT_SIZE 64u
#define TEST_MANIFEST_DESCRIPTOR_FLAGS_OFFSET (FILE_OBJECT_MANIFEST_HEADER_SIZE + 28u)
#define TEST_MANIFEST_DESCRIPTOR_EXTENSION_OFFSET (FILE_OBJECT_MANIFEST_HEADER_SIZE + 30u)
#define TEST_MANIFEST_EXTENSION_SIZE_OFFSET 28u

typedef struct test_file {
    file_t file;
    uint8_t storage[TEST_FILE_CAPACITY];
    uint32_t size;
    bool allocated;
} test_file_t;

typedef struct test_file_image {
    uint8_t storage[TEST_FILE_CAPACITY];
    uint32_t size;
    uint16_t fid;
    bool allocated;
} test_file_image_t;

static test_file_t test_files[TEST_FILE_COUNT];
static test_file_image_t test_durable_files[TEST_FILE_COUNT];
static uint16_t test_fail_write_fid;
static size_t test_fail_write_after = SIZE_MAX;
static size_t test_commit_count;
static size_t test_fail_commit = SIZE_MAX;

static const file_object_txn_layout_t test_txn_layout = {
    .namespace_id = 0x1001,
    .object_type = 0x2001,
    .object_id = 0x01020304,
    .record_fid = { 0xd001, 0xd101 },
    .commit_fid = { 0xd201, 0xd301 }
};

typedef struct test_auth_context {
    uint32_t state[4];
    bool active;
} test_auth_context_t;

static test_auth_context_t test_auth_context;

typedef struct test_record_protector_context {
    uint8_t key;
} test_record_protector_context_t;

static test_record_protector_context_t test_record_protector_context = { .key = 0x5a };

static int test_auth_start(void *ctx) {
    test_auth_context_t *auth = (test_auth_context_t *)ctx;
    auth->state[0] = 0x811c9dc5u;
    auth->state[1] = 0x9e3779b9u;
    auth->state[2] = 0x85ebca6bu;
    auth->state[3] = 0xc2b2ae35u;
    auth->active = true;
    return PICOKEYS_OK;
}

static int test_auth_update(void *ctx, const uint8_t *data, size_t len) {
    test_auth_context_t *auth = (test_auth_context_t *)ctx;
    if (!auth->active || (!data && len > 0)) {
        return PICOKEYS_EXEC_ERROR;
    }
    for (size_t i = 0; i < len; i++) {
        for (size_t word = 0; word < 4; word++) {
            auth->state[word] ^= data[i] + (uint8_t)word;
            auth->state[word] *= 0x01000193u + (uint32_t)(word * 2u);
            auth->state[word] = (auth->state[word] << 5) | (auth->state[word] >> 27);
        }
    }
    return PICOKEYS_OK;
}

static int test_auth_finish(void *ctx, uint8_t tag[FILE_OBJECT_AUTH_TAG_SIZE]) {
    test_auth_context_t *auth = (test_auth_context_t *)ctx;
    if (!auth->active || !tag) {
        return PICOKEYS_EXEC_ERROR;
    }
    for (size_t i = 0; i < 4; i++) {
        put_uint32_be(auth->state[i], tag + i * sizeof(uint32_t));
    }
    memset(auth->state, 0, sizeof(auth->state));
    auth->active = false;
    return PICOKEYS_OK;
}

static void test_auth_abort(void *ctx) {
    test_auth_context_t *auth = (test_auth_context_t *)ctx;
    memset(auth, 0, sizeof(*auth));
}

static const file_object_authenticator_t test_auth = {
    .ctx = &test_auth_context,
    .start = test_auth_start,
    .update = test_auth_update,
    .finish = test_auth_finish,
    .abort = test_auth_abort
};

static int test_record_tag(test_record_protector_context_t *protector, const uint8_t nonce[FILE_OBJECT_RECORD_NONCE_SIZE], const uint8_t aad[FILE_OBJECT_RECORD_AAD_SIZE], const uint8_t *stored, size_t len, uint8_t tag[FILE_OBJECT_AUTH_TAG_SIZE]) {
    int r = test_auth_start(&test_auth_context);
    if (r == PICOKEYS_OK) {
        r = test_auth_update(&test_auth_context, &protector->key, sizeof(protector->key));
    }
    if (r == PICOKEYS_OK) {
        r = test_auth_update(&test_auth_context, aad, FILE_OBJECT_RECORD_AAD_SIZE);
    }
    if (r == PICOKEYS_OK) {
        r = test_auth_update(&test_auth_context, nonce, FILE_OBJECT_RECORD_NONCE_SIZE);
    }
    if (r == PICOKEYS_OK) {
        r = test_auth_update(&test_auth_context, stored, len);
    }
    if (r == PICOKEYS_OK) {
        r = test_auth_finish(&test_auth_context, tag);
    }
    if (r != PICOKEYS_OK) {
        test_auth_abort(&test_auth_context);
    }
    return r;
}

static int test_record_seal(void *ctx, const file_object_record_identity_t *identity, const uint8_t nonce[FILE_OBJECT_RECORD_NONCE_SIZE], const uint8_t aad[FILE_OBJECT_RECORD_AAD_SIZE], const uint8_t *plaintext, size_t len, uint8_t *stored, uint8_t tag[FILE_OBJECT_AUTH_TAG_SIZE]) {
    test_record_protector_context_t *protector = (test_record_protector_context_t *)ctx;
    if (!protector || !identity || !nonce || !aad || (!plaintext && len > 0) || !stored || !tag) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    for (size_t i = 0; i < len; i++) {
        stored[i] = identity->protection == FILE_OBJECT_PROTECTION_AEAD_SECRET ? plaintext[i] ^ protector->key ^ nonce[i % FILE_OBJECT_RECORD_NONCE_SIZE] : plaintext[i];
    }
    return test_record_tag(protector, nonce, aad, stored, len, tag);
}

static int test_record_unseal(void *ctx, const file_object_record_identity_t *identity, const uint8_t nonce[FILE_OBJECT_RECORD_NONCE_SIZE], const uint8_t aad[FILE_OBJECT_RECORD_AAD_SIZE], const uint8_t *stored, size_t len, const uint8_t tag[FILE_OBJECT_AUTH_TAG_SIZE], uint8_t *plaintext) {
    test_record_protector_context_t *protector = (test_record_protector_context_t *)ctx;
    uint8_t calculated_tag[FILE_OBJECT_AUTH_TAG_SIZE];
    int r = test_record_tag(protector, nonce, aad, stored, len, calculated_tag);
    uint8_t difference = 0;
    if (r == PICOKEYS_OK) {
        for (size_t i = 0; i < sizeof(calculated_tag); i++) {
            difference |= calculated_tag[i] ^ tag[i];
        }
        if (difference != 0) {
            r = PICOKEYS_WRONG_SIGNATURE;
        }
    }
    memset(calculated_tag, 0, sizeof(calculated_tag));
    if (r != PICOKEYS_OK) {
        return r;
    }
    for (size_t i = 0; i < len; i++) {
        plaintext[i] = identity->protection == FILE_OBJECT_PROTECTION_AEAD_SECRET ? stored[i] ^ protector->key ^ nonce[i % FILE_OBJECT_RECORD_NONCE_SIZE] : stored[i];
    }
    return PICOKEYS_OK;
}

static const file_object_record_protector_t test_record_protector = {
    .ctx = &test_record_protector_context,
    .seal = test_record_seal,
    .unseal = test_record_unseal
};

static bool test_extension_supported(void *ctx, uint8_t kind) {
    const uint8_t *supported_kind = (const uint8_t *)ctx;
    return supported_kind && kind == *supported_kind;
}

static void test_manifest_retag(uint8_t *data, size_t len) {
    assert(len >= FILE_OBJECT_AUTH_TAG_SIZE);
    assert(test_auth_start(&test_auth_context) == PICOKEYS_OK);
    assert(test_auth_update(&test_auth_context, data, len - FILE_OBJECT_AUTH_TAG_SIZE) == PICOKEYS_OK);
    assert(test_auth_finish(&test_auth_context, data + len - FILE_OBJECT_AUTH_TAG_SIZE) == PICOKEYS_OK);
}

static file_object_manifest_t test_manifest_value(void) {
    return (file_object_manifest_t) {
        .namespace_id = 0x1001,
        .container_kind = 0x0001,
        .container_id = 0x01020304,
        .generation = 2,
        .previous_generation = 1,
        .has_object = true,
        .object = {
            .object_type = 0x0008,
            .object_tag = 0x0002,
            .generation = 3,
            .logical_size = 3,
            .record_id = UINT64_C(0x0102030412345678),
            .stored_size = 3,
            .policy_id = 0x0001,
            .protection = FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC,
            .flags = FILE_OBJECT_FLAG_MUTABLE | FILE_OBJECT_FLAG_GENERIC_READABLE
        }
    };
}

static test_file_t *test_file_from_handle(const file_t *file) {
    for (size_t i = 0; i < TEST_FILE_COUNT; i++) {
        if (&test_files[i].file == file) {
            return &test_files[i];
        }
    }
    return NULL;
}

static void test_files_reset(void) {
    memset(test_files, 0, sizeof(test_files));
    memset(test_durable_files, 0, sizeof(test_durable_files));
    test_fail_write_fid = 0;
    test_fail_write_after = SIZE_MAX;
    test_commit_count = 0;
    test_fail_commit = SIZE_MAX;
    test_auth_abort(&test_auth_context);
}

static void test_persist_files(void) {
    for (size_t i = 0; i < TEST_FILE_COUNT; i++) {
        memcpy(test_durable_files[i].storage, test_files[i].storage, sizeof(test_durable_files[i].storage));
        test_durable_files[i].size = test_files[i].size;
        test_durable_files[i].fid = test_files[i].file.fid;
        test_durable_files[i].allocated = test_files[i].allocated;
    }
}

static void test_reboot(void) {
    memset(test_files, 0, sizeof(test_files));
    for (size_t i = 0; i < TEST_FILE_COUNT; i++) {
        memcpy(test_files[i].storage, test_durable_files[i].storage, sizeof(test_files[i].storage));
        test_files[i].size = test_durable_files[i].size;
        test_files[i].file.fid = test_durable_files[i].fid;
        test_files[i].allocated = test_durable_files[i].allocated;
        test_files[i].file.data = test_files[i].size > 0 ? test_files[i].storage : NULL;
    }
    test_fail_write_fid = 0;
    test_fail_write_after = SIZE_MAX;
    test_fail_commit = SIZE_MAX;
    test_auth_abort(&test_auth_context);
}

file_t *file_search(uint16_t fid) {
    for (size_t i = 0; i < TEST_FILE_COUNT; i++) {
        if (test_files[i].allocated && test_files[i].file.fid == fid) {
            return &test_files[i].file;
        }
    }
    return NULL;
}

file_t *file_new(uint16_t fid) {
    file_t *existing = file_search(fid);
    if (existing) {
        return existing;
    }
    for (size_t i = 0; i < TEST_FILE_COUNT; i++) {
        if (!test_files[i].allocated) {
            test_files[i].allocated = true;
            test_files[i].file.fid = fid;
            return &test_files[i].file;
        }
    }
    return NULL;
}

file_t *file_search_by_fid(const uint16_t fid, const file_t *parent, const uint8_t sp) {
    (void)fid;
    (void)parent;
    (void)sp;
    return NULL;
}

bool file_has_data(const file_t *file) {
    test_file_t *test_file = test_file_from_handle(file);
    return test_file && test_file->allocated && test_file->file.data && test_file->size > 0;
}

uint32_t file_get_size(const file_t *file) {
    test_file_t *test_file = test_file_from_handle(file);
    return test_file ? test_file->size : 0;
}

int file_read_at(const file_t *file, uint32_t offset, uint8_t *data, size_t len) {
    test_file_t *test_file = test_file_from_handle(file);
    if (!test_file || (!data && len > 0) || offset > test_file->size || len > test_file->size - offset) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    if (len > 0) {
        memcpy(data, test_file->storage + offset, len);
    }
    return PICOKEYS_OK;
}

int file_put_data(file_t *file, const uint8_t *data, uint32_t len) {
    test_file_t *test_file = test_file_from_handle(file);
    if (!test_file || (!data && len > 0) || len > sizeof(test_file->storage)) {
        return PICOKEYS_ERR_NO_MEMORY;
    }
    size_t written = len;
    bool fail = file->fid == test_fail_write_fid && test_fail_write_after < len;
    if (fail) {
        written = test_fail_write_after;
    }
    if (written > 0) {
        memcpy(test_file->storage, data, written);
    }
    test_file->size = (uint32_t)written;
    test_file->file.data = written > 0 ? test_file->storage : NULL;
    return fail ? PICOKEYS_EXEC_ERROR : PICOKEYS_OK;
}

int file_delete_no_commit(file_t *file) {
    test_file_t *test_file = test_file_from_handle(file);
    if (!test_file || !test_file->allocated) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    memset(test_file->storage, 0, sizeof(test_file->storage));
    test_file->file.data = NULL;
    test_file->size = 0;
    return PICOKEYS_OK;
}

int file_delete(file_t *file) {
    return file_delete_no_commit(file);
}

bool flash_commit_sync(uint32_t timeout_ms) {
    (void)timeout_ms;
    test_commit_count++;
    if (test_commit_count == test_fail_commit) {
        return false;
    }
    test_persist_files();
    return true;
}

static void test_txn_read(const file_object_txn_layout_t *layout, const uint8_t *expected, size_t expected_len, uint32_t expected_generation) {
    file_object_txn_handle_t handle = FILE_OBJECT_TXN_INVALID_HANDLE;
    file_object_info_t info;
    uint8_t output[32] = { 0 };

    assert(expected_len <= sizeof(output));
    assert(file_object_txn_open(layout, &test_auth, &handle) == PICOKEYS_OK);
    assert(file_object_txn_get_info(handle, &test_auth, &info) == PICOKEYS_OK);
    assert(info.generation == expected_generation);
    assert(info.payload_size == expected_len);
    assert(file_object_txn_read_at(handle, &test_auth, 0, output, expected_len) == PICOKEYS_OK);
    assert(memcmp(output, expected, expected_len) == 0);
    assert(file_object_txn_close(handle) == PICOKEYS_OK);
}

static void test_identity_and_stale_handles(void) {
    static const uint8_t first[] = { 1, 2, 3, 4 };
    static const uint8_t second[] = { 5, 6, 7 };
    const file_object_id_t object_id = { .namespace_id = 1, .object_type = 2, .fid = 0xc701 };
    const file_object_id_t wrong_namespace = { .namespace_id = 2, .object_type = 2, .fid = 0xc701 };
    const file_object_id_t wrong_type = { .namespace_id = 1, .object_type = 3, .fid = 0xc701 };
    file_object_handle_t first_handle = FILE_OBJECT_INVALID_HANDLE;
    file_object_handle_t second_handle = FILE_OBJECT_INVALID_HANDLE;
    file_object_info_t info;
    uint8_t output[sizeof(first)] = { 0 };

    assert(file_object_put(&object_id, first, sizeof(first)) == PICOKEYS_OK);
    assert(file_object_open(&wrong_namespace, &first_handle) == PICOKEYS_WRONG_DATA);
    assert(first_handle == FILE_OBJECT_INVALID_HANDLE);
    assert(file_object_open(&wrong_type, &first_handle) == PICOKEYS_WRONG_DATA);
    assert(file_object_open(&object_id, &first_handle) == PICOKEYS_OK);
    assert(file_object_get_info(first_handle, &info) == PICOKEYS_OK);
    assert(info.generation == 1);
    assert(info.payload_size == sizeof(first));
    assert(file_object_read_at(first_handle, 1, output, 2) == PICOKEYS_OK);
    assert(memcmp(output, first + 1, 2) == 0);
    assert(file_object_read_at(first_handle, sizeof(first), output, 1) == PICOKEYS_WRONG_LENGTH);

    assert(file_object_put(&object_id, second, sizeof(second)) == PICOKEYS_OK);
    assert(file_object_read_at(first_handle, 0, output, 1) == PICOKEYS_ERR_STALE_HANDLE);
    assert(file_object_close(first_handle) == PICOKEYS_OK);
    assert(file_object_read_at(first_handle, 0, output, 1) == PICOKEYS_ERR_STALE_HANDLE);

    assert(file_object_open(&object_id, &second_handle) == PICOKEYS_OK);
    assert(file_object_get_info(second_handle, &info) == PICOKEYS_OK);
    assert(info.generation == 2);
    assert(info.payload_size == sizeof(second));
    memset(output, 0, sizeof(output));
    assert(file_object_read_at(second_handle, 0, output, sizeof(second)) == PICOKEYS_OK);
    assert(memcmp(output, second, sizeof(second)) == 0);

    assert(file_object_delete_no_commit(&object_id) == PICOKEYS_OK);
    assert(file_object_read_at(second_handle, 0, output, 1) == PICOKEYS_ERR_STALE_HANDLE);
    assert(file_object_close(second_handle) == PICOKEYS_OK);
}

static void test_fid_binding_and_malformed_header(void) {
    static const uint8_t payload[] = { 9, 8, 7, 6 };
    const file_object_id_t source_id = { .namespace_id = 1, .object_type = 2, .fid = 0xc711 };
    const file_object_id_t copied_id = { .namespace_id = 1, .object_type = 2, .fid = 0xc712 };
    file_object_handle_t handle = FILE_OBJECT_INVALID_HANDLE;

    assert(file_object_put(&source_id, payload, sizeof(payload)) == PICOKEYS_OK);
    file_t *source = file_search(source_id.fid);
    file_t *copied = file_new(copied_id.fid);
    assert(source && copied);
    assert(file_put_data(copied, test_file_from_handle(source)->storage, file_get_size(source)) == PICOKEYS_OK);
    assert(file_object_open(&copied_id, &handle) == PICOKEYS_WRONG_DATA);
    assert(handle == FILE_OBJECT_INVALID_HANDLE);

    test_file_t *source_file = test_file_from_handle(source);
    source_file->storage[4] = 0xff;
    assert(file_object_open(&source_id, &handle) == PICOKEYS_WRONG_DATA);
}

static void test_handle_capacity(void) {
    static const uint8_t payload[] = { 1 };
    const file_object_id_t object_id = { .namespace_id = 3, .object_type = 4, .fid = 0xc721 };
    file_object_handle_t handles[FILE_OBJECT_MAX_HANDLES];
    file_object_handle_t extra = FILE_OBJECT_INVALID_HANDLE;

    assert(file_object_put(&object_id, payload, sizeof(payload)) == PICOKEYS_OK);
    for (size_t i = 0; i < FILE_OBJECT_MAX_HANDLES; i++) {
        assert(file_object_open(&object_id, &handles[i]) == PICOKEYS_OK);
    }
    assert(file_object_open(&object_id, &extra) == PICOKEYS_ERR_NO_MEMORY);
    assert(extra == FILE_OBJECT_INVALID_HANDLE);
    for (size_t i = 0; i < FILE_OBJECT_MAX_HANDLES; i++) {
        assert(file_object_close(handles[i]) == PICOKEYS_OK);
    }
}

static void test_transaction_replacement_and_delete(void) {
    static const uint8_t first[] = { 1, 3, 5, 7 };
    static const uint8_t second[] = { 2, 4, 6, 8, 10 };
    static const uint8_t third[] = { 11, 12, 13 };
    file_object_txn_handle_t stale_handle = FILE_OBJECT_TXN_INVALID_HANDLE;
    uint8_t output = 0;

    assert(file_object_txn_put(&test_txn_layout, &test_auth, first, sizeof(first)) == PICOKEYS_OK);
    test_txn_read(&test_txn_layout, first, sizeof(first), 1);
    assert(file_object_txn_open(&test_txn_layout, &test_auth, &stale_handle) == PICOKEYS_OK);

    assert(file_object_txn_put(&test_txn_layout, &test_auth, second, sizeof(second)) == PICOKEYS_OK);
    assert(file_object_txn_read_at(stale_handle, &test_auth, 0, &output, 1) == PICOKEYS_ERR_STALE_HANDLE);
    assert(file_object_txn_close(stale_handle) == PICOKEYS_OK);
    test_txn_read(&test_txn_layout, second, sizeof(second), 2);

    assert(file_object_txn_open(&test_txn_layout, &test_auth, &stale_handle) == PICOKEYS_OK);
    assert(file_object_txn_delete(&test_txn_layout, &test_auth) == PICOKEYS_OK);
    assert(file_object_txn_read_at(stale_handle, &test_auth, 0, &output, 1) == PICOKEYS_ERR_STALE_HANDLE);
    assert(file_object_txn_close(stale_handle) == PICOKEYS_OK);
    assert(file_object_txn_open(&test_txn_layout, &test_auth, &stale_handle) == PICOKEYS_ERR_FILE_NOT_FOUND);

    assert(file_object_txn_put(&test_txn_layout, &test_auth, third, sizeof(third)) == PICOKEYS_OK);
    test_txn_read(&test_txn_layout, third, sizeof(third), 4);
}

static void test_transaction_commit_boundaries(void) {
    static const uint8_t first[] = { 0x10, 0x11, 0x12 };
    static const uint8_t second[] = { 0x20, 0x21, 0x22, 0x23 };

    assert(file_object_txn_put(&test_txn_layout, &test_auth, first, sizeof(first)) == PICOKEYS_OK);
    test_fail_commit = test_commit_count + 1;
    assert(file_object_txn_put(&test_txn_layout, &test_auth, second, sizeof(second)) == PICOKEYS_ERR_MEMORY_FATAL);
    test_reboot();
    test_txn_read(&test_txn_layout, first, sizeof(first), 1);

    test_files_reset();
    assert(file_object_txn_put(&test_txn_layout, &test_auth, first, sizeof(first)) == PICOKEYS_OK);
    test_fail_commit = test_commit_count + 2;
    assert(file_object_txn_put(&test_txn_layout, &test_auth, second, sizeof(second)) == PICOKEYS_ERR_MEMORY_FATAL);
    test_reboot();
    test_txn_read(&test_txn_layout, first, sizeof(first), 1);
}

static void test_transaction_record_write_boundaries(void) {
    static const uint8_t first[] = { 0x31, 0x32, 0x33 };
    static const uint8_t second[] = { 0x41, 0x42, 0x43, 0x44 };
    const size_t record_size = TEST_TXN_RECORD_HEADER_SIZE + sizeof(second) + FILE_OBJECT_AUTH_TAG_SIZE;

    for (size_t written = 0; written < record_size; written++) {
        test_files_reset();
        assert(file_object_txn_put(&test_txn_layout, &test_auth, first, sizeof(first)) == PICOKEYS_OK);
        test_fail_write_fid = test_txn_layout.record_fid[1];
        test_fail_write_after = written;
        assert(file_object_txn_put(&test_txn_layout, &test_auth, second, sizeof(second)) == PICOKEYS_EXEC_ERROR);
        test_persist_files();
        test_reboot();
        test_txn_read(&test_txn_layout, first, sizeof(first), 1);
    }
}

static void test_transaction_commit_write_boundaries(void) {
    static const uint8_t first[] = { 0x51, 0x52, 0x53 };
    static const uint8_t second[] = { 0x61, 0x62, 0x63, 0x64 };

    for (size_t written = 0; written < TEST_TXN_COMMIT_SIZE; written++) {
        test_files_reset();
        assert(file_object_txn_put(&test_txn_layout, &test_auth, first, sizeof(first)) == PICOKEYS_OK);
        test_fail_write_fid = test_txn_layout.commit_fid[1];
        test_fail_write_after = written;
        assert(file_object_txn_put(&test_txn_layout, &test_auth, second, sizeof(second)) == PICOKEYS_EXEC_ERROR);
        test_persist_files();
        test_reboot();
        test_txn_read(&test_txn_layout, first, sizeof(first), 1);
    }
}

static void test_transaction_corruption_falls_back(void) {
    static const uint8_t first[] = { 0x71, 0x72, 0x73 };
    static const uint8_t second[] = { 0x81, 0x82, 0x83, 0x84 };

    assert(file_object_txn_put(&test_txn_layout, &test_auth, first, sizeof(first)) == PICOKEYS_OK);
    assert(file_object_txn_put(&test_txn_layout, &test_auth, second, sizeof(second)) == PICOKEYS_OK);
    test_file_t *record = test_file_from_handle(file_search(test_txn_layout.record_fid[1]));
    assert(record && record->size > TEST_TXN_RECORD_HEADER_SIZE);
    record->storage[TEST_TXN_RECORD_HEADER_SIZE] ^= 0x80;
    test_persist_files();
    test_reboot();
    test_txn_read(&test_txn_layout, first, sizeof(first), 1);

    test_files_reset();
    assert(file_object_txn_put(&test_txn_layout, &test_auth, first, sizeof(first)) == PICOKEYS_OK);
    assert(file_object_txn_put(&test_txn_layout, &test_auth, second, sizeof(second)) == PICOKEYS_OK);
    test_file_t *commit = test_file_from_handle(file_search(test_txn_layout.commit_fid[1]));
    assert(commit && commit->size == TEST_TXN_COMMIT_SIZE);
    commit->storage[TEST_TXN_COMMIT_SIZE - 1] ^= 0x01;
    test_persist_files();
    test_reboot();
    test_txn_read(&test_txn_layout, first, sizeof(first), 1);
}

static void test_transaction_identity_isolation(void) {
    static const uint8_t payload[] = { 0x91, 0x92, 0x93 };
    file_object_txn_layout_t wrong_layout = test_txn_layout;
    file_object_txn_handle_t handle = FILE_OBJECT_TXN_INVALID_HANDLE;

    assert(file_object_txn_put(&test_txn_layout, &test_auth, payload, sizeof(payload)) == PICOKEYS_OK);
    wrong_layout.namespace_id++;
    assert(file_object_txn_open(&wrong_layout, &test_auth, &handle) == PICOKEYS_ERR_FILE_NOT_FOUND);
    wrong_layout = test_txn_layout;
    wrong_layout.object_type++;
    assert(file_object_txn_open(&wrong_layout, &test_auth, &handle) == PICOKEYS_ERR_FILE_NOT_FOUND);
    wrong_layout = test_txn_layout;
    wrong_layout.object_id++;
    assert(file_object_txn_open(&wrong_layout, &test_auth, &handle) == PICOKEYS_ERR_FILE_NOT_FOUND);
}

static void test_manifest_round_trip(void) {
    static const uint8_t extensions[] = { 0x80, 0x00, 0x00, 0x03, 0xaa, 0xbb, 0xcc };
    file_object_manifest_t source = test_manifest_value();
    file_object_manifest_t parsed;
    uint8_t data[128];
    size_t written = 0;

    source.object.extension_offset = FILE_OBJECT_MANIFEST_HEADER_SIZE + FILE_OBJECT_DESCRIPTOR_SIZE;
    source.object.extension_size = sizeof(extensions);
    assert(file_object_manifest_build(&source, extensions, sizeof(extensions), &test_auth, data, sizeof(data), &written) == PICOKEYS_OK);
    assert(written == FILE_OBJECT_MANIFEST_HEADER_SIZE + FILE_OBJECT_DESCRIPTOR_SIZE + sizeof(extensions) + FILE_OBJECT_AUTH_TAG_SIZE);
    assert(file_object_manifest_parse(data, written, &test_auth, NULL, NULL, &parsed) == PICOKEYS_OK);
    assert(parsed.namespace_id == source.namespace_id);
    assert(parsed.container_kind == source.container_kind);
    assert(parsed.container_id == source.container_id);
    assert(parsed.generation == source.generation);
    assert(parsed.previous_generation == source.previous_generation);
    assert(parsed.has_object);
    assert(parsed.object_count == 1);
    assert(parsed.object.object_type == source.object.object_type);
    assert(parsed.object.object_tag == source.object.object_tag);
    assert(parsed.object.record_id == source.object.record_id);
    assert(parsed.object.flags == source.object.flags);
    assert(parsed.extension_size == sizeof(extensions));
    assert(memcmp(data + parsed.extension_offset, extensions, sizeof(extensions)) == 0);
    for (size_t truncated = 0; truncated < written; truncated++) {
        assert(file_object_manifest_parse(data, truncated, &test_auth, NULL, NULL, &parsed) != PICOKEYS_OK);
    }

    data[8] ^= 0x01;
    assert(file_object_manifest_parse(data, written, &test_auth, NULL, NULL, &parsed) == PICOKEYS_WRONG_SIGNATURE);
    data[8] ^= 0x01;
    assert(file_object_manifest_build(&source, extensions, sizeof(extensions), &test_auth, data, written - 1, &written) == PICOKEYS_WRONG_LENGTH);
    assert(written == 0);
}

static void test_multi_object_manifest_round_trip(void) {
    file_object_manifest_t source = test_manifest_value();
    file_object_manifest_t parsed;
    uint8_t data[256];
    size_t written = 0;

    source.object_count = 3;
    source.objects[1] = source.objects[0];
    source.objects[1].object_type++;
    source.objects[1].object_tag = 0;
    source.objects[1].record_id++;
    source.objects[2] = source.objects[1];
    source.objects[2].object_tag = 1;
    source.objects[2].record_id++;

    assert(file_object_manifest_build(&source, NULL, 0, &test_auth, data, sizeof(data), &written) == PICOKEYS_OK);
    assert(written == FILE_OBJECT_MANIFEST_HEADER_SIZE + 3 * FILE_OBJECT_DESCRIPTOR_SIZE + FILE_OBJECT_AUTH_TAG_SIZE);
    assert(file_object_manifest_parse(data, written, &test_auth, NULL, NULL, &parsed) == PICOKEYS_OK);
    assert(parsed.object_count == 3);
    assert(parsed.has_object);
    assert(parsed.objects[0].record_id == source.objects[0].record_id);
    assert(parsed.objects[1].record_id == source.objects[1].record_id);
    assert(parsed.objects[2].record_id == source.objects[2].record_id);

    file_object_descriptor_t unordered = source.objects[0];
    source.objects[0] = source.objects[1];
    source.objects[1] = unordered;
    assert(file_object_manifest_build(&source, NULL, 0, &test_auth, data, sizeof(data), &written) == PICOKEYS_WRONG_DATA);

    source.objects[0] = source.objects[1];
    source.objects[0].record_id--;
    assert(file_object_manifest_build(&source, NULL, 0, &test_auth, data, sizeof(data), &written) == PICOKEYS_WRONG_DATA);
}

static void test_manifest_extension_compatibility(void) {
    static const uint8_t critical_extension[] = { 0x81, FILE_OBJECT_EXTENSION_FLAG_CRITICAL, 0x00, 0x01, 0x42 };
    static const uint8_t malformed_extension[] = { 0x82, 0x00, 0x00, 0x02, 0x42 };
    const uint8_t supported_kind = 0x81;
    file_object_manifest_t source = test_manifest_value();
    file_object_manifest_t parsed;
    uint8_t data[128];
    size_t written = 0;

    source.object.extension_offset = FILE_OBJECT_MANIFEST_HEADER_SIZE + FILE_OBJECT_DESCRIPTOR_SIZE;
    source.object.extension_size = sizeof(critical_extension);
    assert(file_object_manifest_build(&source, critical_extension, sizeof(critical_extension), &test_auth, data, sizeof(data), &written) == PICOKEYS_OK);
    assert(file_object_manifest_parse(data, written, &test_auth, NULL, NULL, &parsed) == PICOKEYS_WRONG_DATA);
    assert(file_object_manifest_parse(data, written, &test_auth, test_extension_supported, (void *)&supported_kind, &parsed) == PICOKEYS_OK);
    assert(memcmp(data + parsed.extension_offset, critical_extension, sizeof(critical_extension)) == 0);

    source.object.extension_offset++;
    source.object.extension_size--;
    assert(file_object_manifest_build(&source, critical_extension, sizeof(critical_extension), &test_auth, data, sizeof(data), &written) == PICOKEYS_WRONG_DATA);

    source.object.extension_offset = FILE_OBJECT_MANIFEST_HEADER_SIZE + FILE_OBJECT_DESCRIPTOR_SIZE;
    source.object.extension_size = sizeof(malformed_extension);
    assert(file_object_manifest_build(&source, malformed_extension, sizeof(malformed_extension), &test_auth, data, sizeof(data), &written) == PICOKEYS_WRONG_DATA);
}

static void test_manifest_malformed_fields(void) {
    file_object_manifest_t source = test_manifest_value();
    file_object_manifest_t parsed;
    uint8_t data[128];
    size_t written = 0;

    source.object.flags |= 0x8000;
    assert(file_object_manifest_build(&source, NULL, 0, &test_auth, data, sizeof(data), &written) == PICOKEYS_WRONG_DATA);
    source = test_manifest_value();
    source.object.flags |= FILE_OBJECT_FLAG_INLINE;
    assert(file_object_manifest_build(&source, NULL, 0, &test_auth, data, sizeof(data), &written) == PICOKEYS_WRONG_DATA);
    source = test_manifest_value();
    source.object.flags |= FILE_OBJECT_FLAG_TRANSACTION_GROUP;
    assert(file_object_manifest_build(&source, NULL, 0, &test_auth, data, sizeof(data), &written) == PICOKEYS_WRONG_DATA);

    source = test_manifest_value();
    assert(file_object_manifest_build(&source, NULL, 0, &test_auth, data, sizeof(data), &written) == PICOKEYS_OK);
    put_uint16_be(2, data + 24);
    assert(file_object_manifest_parse(data, written, &test_auth, NULL, NULL, &parsed) == PICOKEYS_WRONG_DATA);

    assert(file_object_manifest_build(&source, NULL, 0, &test_auth, data, sizeof(data), &written) == PICOKEYS_OK);
    put_uint16_be(0x8000, data + TEST_MANIFEST_DESCRIPTOR_FLAGS_OFFSET);
    test_manifest_retag(data, written);
    assert(file_object_manifest_parse(data, written, &test_auth, NULL, NULL, &parsed) == PICOKEYS_WRONG_DATA);

    assert(file_object_manifest_build(&source, NULL, 0, &test_auth, data, sizeof(data), &written) == PICOKEYS_OK);
    put_uint16_be(1, data + TEST_MANIFEST_DESCRIPTOR_EXTENSION_OFFSET);
    test_manifest_retag(data, written);
    assert(file_object_manifest_parse(data, written, &test_auth, NULL, NULL, &parsed) == PICOKEYS_WRONG_DATA);

    assert(file_object_manifest_build(&source, NULL, 0, &test_auth, data, sizeof(data), &written) == PICOKEYS_OK);
    put_uint16_be(1, data + TEST_MANIFEST_EXTENSION_SIZE_OFFSET);
    test_manifest_retag(data, written);
    assert(file_object_manifest_parse(data, written, &test_auth, NULL, NULL, &parsed) == PICOKEYS_WRONG_DATA);
}

static void test_object_record_header_binding(void) {
    file_object_manifest_t manifest = test_manifest_value();
    file_object_record_info_t info;
    uint8_t record[FILE_OBJECT_RECORD_HEADER_SIZE + 3 + FILE_OBJECT_AUTH_TAG_SIZE] = { 0 };

    assert(file_object_record_header_build(&manifest.object, record) == PICOKEYS_OK);
    record[FILE_OBJECT_RECORD_HEADER_SIZE] = 1;
    record[FILE_OBJECT_RECORD_HEADER_SIZE + 1] = 2;
    record[FILE_OBJECT_RECORD_HEADER_SIZE + 2] = 3;
    assert(file_object_record_header_parse(record, sizeof(record), &manifest.object, &info) == PICOKEYS_OK);
    assert(info.record_id == manifest.object.record_id);
    assert(info.generation == manifest.object.generation);
    assert(info.payload_offset == FILE_OBJECT_RECORD_HEADER_SIZE);
    assert(info.tag_offset == FILE_OBJECT_RECORD_HEADER_SIZE + manifest.object.stored_size);
    assert(file_object_record_header_parse(record, sizeof(record) - 1, &manifest.object, &info) == PICOKEYS_WRONG_LENGTH);

    record[FILE_OBJECT_RECORD_HEADER_SIZE - 1] ^= 0x01;
    assert(file_object_record_header_parse(record, sizeof(record), &manifest.object, &info) == PICOKEYS_WRONG_DATA);
    record[FILE_OBJECT_RECORD_HEADER_SIZE - 1] ^= 0x01;
    record[8] ^= 0x01;
    assert(file_object_record_header_parse(record, sizeof(record), &manifest.object, &info) == PICOKEYS_WRONG_DATA);
}

static void test_object_record_protection(void) {
    static const uint8_t plaintext[] = { 0x10, 0x20, 0x30 };
    static const uint8_t policy_hash[FILE_OBJECT_POLICY_HASH_SIZE] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    file_object_manifest_t manifest = test_manifest_value();
    file_object_manifest_t relocated;
    uint8_t record[FILE_OBJECT_RECORD_HEADER_SIZE + sizeof(plaintext) + FILE_OBJECT_AUTH_TAG_SIZE];
    uint8_t output[sizeof(plaintext)];
    uint8_t wrong_policy_hash[FILE_OBJECT_POLICY_HASH_SIZE];
    size_t written = 0;

    assert(file_object_record_seal(&manifest, policy_hash, &test_record_protector, plaintext, sizeof(plaintext), record, sizeof(record), &written) == PICOKEYS_OK);
    assert(written == sizeof(record));
    assert(memcmp(record + FILE_OBJECT_RECORD_HEADER_SIZE, plaintext, sizeof(plaintext)) == 0);
    assert(file_object_record_unseal(&manifest, policy_hash, &test_record_protector, record, sizeof(record), output, sizeof(output), &written) == PICOKEYS_OK);
    assert(written == sizeof(plaintext));
    assert(memcmp(output, plaintext, sizeof(plaintext)) == 0);
    assert(file_object_record_unseal(&manifest, policy_hash, &test_record_protector, record, sizeof(record), output, sizeof(output) - 1, &written) == PICOKEYS_WRONG_LENGTH);

    relocated = manifest;
    relocated.container_id++;
    memset(output, 0xa5, sizeof(output));
    assert(file_object_record_unseal(&relocated, policy_hash, &test_record_protector, record, sizeof(record), output, sizeof(output), &written) == PICOKEYS_WRONG_SIGNATURE);
    assert(memcmp(output, (uint8_t[sizeof(output)]) { 0 }, sizeof(output)) == 0);

    memcpy(wrong_policy_hash, policy_hash, sizeof(wrong_policy_hash));
    wrong_policy_hash[0] ^= 0x80;
    assert(file_object_record_unseal(&manifest, wrong_policy_hash, &test_record_protector, record, sizeof(record), output, sizeof(output), &written) == PICOKEYS_WRONG_SIGNATURE);

    record[FILE_OBJECT_RECORD_HEADER_SIZE] ^= 0x01;
    assert(file_object_record_unseal(&manifest, policy_hash, &test_record_protector, record, sizeof(record), output, sizeof(output), &written) == PICOKEYS_WRONG_SIGNATURE);
    record[FILE_OBJECT_RECORD_HEADER_SIZE] ^= 0x01;

    manifest.object.protection = FILE_OBJECT_PROTECTION_AEAD_SECRET;
    manifest.object.flags = FILE_OBJECT_FLAG_NON_EXPORTABLE;
    assert(file_object_record_seal(&manifest, policy_hash, &test_record_protector, plaintext, sizeof(plaintext), record, sizeof(record), &written) == PICOKEYS_OK);
    assert(memcmp(record + FILE_OBJECT_RECORD_HEADER_SIZE, plaintext, sizeof(plaintext)) != 0);
    assert(file_object_record_unseal(&manifest, policy_hash, &test_record_protector, record, sizeof(record), output, sizeof(output), &written) == PICOKEYS_OK);
    assert(memcmp(output, plaintext, sizeof(plaintext)) == 0);

    test_record_protector_context.key ^= 0x01;
    assert(file_object_record_unseal(&manifest, policy_hash, &test_record_protector, record, sizeof(record), output, sizeof(output), &written) == PICOKEYS_WRONG_SIGNATURE);
    test_record_protector_context.key ^= 0x01;
}

static void test_record_id_allocator(void) {
    uint64_t record_id = 0;

    assert(file_object_record_id_allocate(&test_txn_layout, &test_auth, &record_id) == PICOKEYS_OK);
    assert(record_id == 1);
    assert(file_object_record_id_allocate(&test_txn_layout, &test_auth, &record_id) == PICOKEYS_OK);
    assert(record_id == 2);
    test_reboot();
    assert(file_object_record_id_allocate(&test_txn_layout, &test_auth, &record_id) == PICOKEYS_OK);
    assert(record_id == 3);
}

static void test_record_id_allocator_power_loss(void) {
    for (size_t failed_barrier = 1; failed_barrier <= 4; failed_barrier++) {
        test_files_reset();
        uint64_t record_id = 0;
        assert(file_object_record_id_allocate(&test_txn_layout, &test_auth, &record_id) == PICOKEYS_OK);
        assert(record_id == 1);

        test_fail_commit = test_commit_count + failed_barrier;
        record_id = UINT64_MAX;
        assert(file_object_record_id_allocate(&test_txn_layout, &test_auth, &record_id) == PICOKEYS_ERR_MEMORY_FATAL);
        assert(record_id == 0);
        test_reboot();
        assert(file_object_record_id_allocate(&test_txn_layout, &test_auth, &record_id) == PICOKEYS_OK);
        assert(record_id >= 2);
    }
}

static void test_record_id_allocator_single_slot_corruption(void) {
    uint64_t record_id = 0;

    assert(file_object_record_id_allocate(&test_txn_layout, &test_auth, &record_id) == PICOKEYS_OK);
    assert(record_id == 1);
    test_file_t *newest_record = test_file_from_handle(file_search(test_txn_layout.record_fid[1]));
    assert(newest_record && newest_record->size > TEST_TXN_RECORD_HEADER_SIZE);
    newest_record->storage[TEST_TXN_RECORD_HEADER_SIZE] ^= 0x80;
    test_persist_files();
    test_reboot();

    assert(file_object_record_id_allocate(&test_txn_layout, &test_auth, &record_id) == PICOKEYS_OK);
    assert(record_id == 2);
}

int main(void) {
    test_files_reset();
    test_identity_and_stale_handles();
    test_files_reset();
    test_fid_binding_and_malformed_header();
    test_files_reset();
    test_handle_capacity();
    test_files_reset();
    test_transaction_replacement_and_delete();
    test_files_reset();
    test_transaction_commit_boundaries();
    test_files_reset();
    test_transaction_record_write_boundaries();
    test_files_reset();
    test_transaction_commit_write_boundaries();
    test_files_reset();
    test_transaction_corruption_falls_back();
    test_files_reset();
    test_transaction_identity_isolation();
    test_files_reset();
    test_manifest_round_trip();
    test_files_reset();
    test_multi_object_manifest_round_trip();
    test_files_reset();
    test_manifest_extension_compatibility();
    test_files_reset();
    test_manifest_malformed_fields();
    test_files_reset();
    test_object_record_header_binding();
    test_files_reset();
    test_object_record_protection();
    test_files_reset();
    test_record_id_allocator();
    test_files_reset();
    test_record_id_allocator_power_loss();
    test_files_reset();
    test_record_id_allocator_single_slot_corruption();
    puts("object_store_test: OK");
    return 0;
}
