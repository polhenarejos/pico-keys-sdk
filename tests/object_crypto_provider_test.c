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
#include "object_crypto_provider.h"

#include <assert.h>
#include <stdio.h>

#define TEST_NAMESPACE_A 0x1234u
#define TEST_NAMESPACE_B 0x5678u
#define TEST_MAX_KEY_DOMAINS 16u

#define TEST_AAD_NAMESPACE_OFFSET 5u
#define TEST_AAD_KIND_OFFSET 7u
#define TEST_AAD_CONTAINER_ID_OFFSET 9u
#define TEST_AAD_TYPE_OFFSET 13u
#define TEST_AAD_TAG_OFFSET 15u
#define TEST_AAD_GENERATION_OFFSET 17u
#define TEST_AAD_LOGICAL_SIZE_OFFSET 21u
#define TEST_AAD_POLICY_ID_OFFSET 25u
#define TEST_AAD_POLICY_HASH_OFFSET 27u
#define TEST_AAD_KEY_DOMAIN_OFFSET 43u
#define TEST_AAD_PROTECTION_OFFSET 44u
#define TEST_AAD_FLAGS_OFFSET 45u
#define TEST_AAD_RECORD_ID_OFFSET 47u

typedef struct test_root_context {
    uint8_t root[FILE_OBJECT_CRYPTO_ROOT_KEY_SIZE];
    uint8_t public_root[FILE_OBJECT_CRYPTO_ROOT_KEY_SIZE];
    bool available;
    bool public_available;
} test_root_context_t;

static void test_root_reset(test_root_context_t *ctx, uint8_t offset) {
    memset(ctx, 0, sizeof(*ctx));
    for (size_t i = 0; i < sizeof(ctx->root); i++) {
        ctx->root[i] = (uint8_t)(offset + i);
        ctx->public_root[i] = (uint8_t)(offset + 0x40u + i);
    }
    ctx->available = true;
    ctx->public_available = true;
}

static int test_public_root_load(void *ctx, uint8_t root[FILE_OBJECT_CRYPTO_ROOT_KEY_SIZE]) {
    test_root_context_t *root_ctx = (test_root_context_t *)ctx;
    if (!root_ctx->public_available) {
        return PICOKEYS_NO_LOGIN;
    }
    memcpy(root, root_ctx->public_root, FILE_OBJECT_CRYPTO_ROOT_KEY_SIZE);
    return PICOKEYS_OK;
}

static int test_root_load(void *ctx, uint8_t root[FILE_OBJECT_CRYPTO_ROOT_KEY_SIZE]) {
    test_root_context_t *root_ctx = (test_root_context_t *)ctx;
    if (!root_ctx->available) {
        return PICOKEYS_NO_LOGIN;
    }
    memcpy(root, root_ctx->root, FILE_OBJECT_CRYPTO_ROOT_KEY_SIZE);
    return PICOKEYS_OK;
}

static bool test_identity_valid(void *ctx, const file_object_record_identity_t *identity) {
    (void)ctx;
    return identity->key_domain < TEST_MAX_KEY_DOMAINS;
}

static void test_provider_init(file_object_crypto_provider_t *provider, test_root_context_t *root, uint16_t namespace_id) {
    const file_object_crypto_provider_config_t config = {
        .ctx = root,
        .namespace_id = namespace_id,
        .load_root = test_root_load,
        .load_public_root = test_public_root_load,
        .identity_valid = test_identity_valid
    };
    assert(file_object_crypto_provider_init(provider, &config) == PICOKEYS_OK);
}

static file_object_record_identity_t test_identity(uint16_t namespace_id, uint8_t protection) {
    file_object_record_identity_t identity = {
        .namespace_id = namespace_id,
        .container_kind = 1,
        .container_id = 0x01020304,
        .object_type = 1,
        .object_tag = 2,
        .generation = 3,
        .logical_size = 5,
        .policy_id = 0x0101,
        .key_domain = 1,
        .protection = protection,
        .flags = FILE_OBJECT_FLAG_NON_EXPORTABLE,
        .record_id = UINT64_C(0x0102030405060708)
    };
    for (size_t i = 0; i < sizeof(identity.policy_hash); i++) {
        identity.policy_hash[i] = (uint8_t)(0xa0 + i);
    }
    return identity;
}

static void test_aad_build(const file_object_record_identity_t *identity, uint8_t aad[FILE_OBJECT_RECORD_AAD_SIZE], uint8_t nonce[FILE_OBJECT_RECORD_NONCE_SIZE]) {
    memset(aad, 0, FILE_OBJECT_RECORD_AAD_SIZE);
    memcpy(aad, "PKOR", 4);
    aad[4] = FILE_OBJECT_RECORD_FORMAT_VERSION;
    put_uint16_be(identity->namespace_id, aad + TEST_AAD_NAMESPACE_OFFSET);
    put_uint16_be(identity->container_kind, aad + TEST_AAD_KIND_OFFSET);
    put_uint32_be(identity->container_id, aad + TEST_AAD_CONTAINER_ID_OFFSET);
    put_uint16_be(identity->object_type, aad + TEST_AAD_TYPE_OFFSET);
    put_uint16_be(identity->object_tag, aad + TEST_AAD_TAG_OFFSET);
    put_uint32_be(identity->generation, aad + TEST_AAD_GENERATION_OFFSET);
    put_uint32_be(identity->logical_size, aad + TEST_AAD_LOGICAL_SIZE_OFFSET);
    put_uint16_be(identity->policy_id, aad + TEST_AAD_POLICY_ID_OFFSET);
    memcpy(aad + TEST_AAD_POLICY_HASH_OFFSET, identity->policy_hash, FILE_OBJECT_POLICY_HASH_SIZE);
    aad[TEST_AAD_KEY_DOMAIN_OFFSET] = identity->key_domain;
    aad[TEST_AAD_PROTECTION_OFFSET] = identity->protection;
    put_uint16_be(identity->flags, aad + TEST_AAD_FLAGS_OFFSET);
    put_uint64_be(identity->record_id, aad + TEST_AAD_RECORD_ID_OFFSET);
    put_uint64_be(identity->record_id, nonce);
    put_uint32_be(identity->generation, nonce + sizeof(uint64_t));
}

static void test_manifest_tag(file_object_crypto_provider_t *provider, const uint8_t *data, size_t len, uint8_t tag[FILE_OBJECT_AUTH_TAG_SIZE]) {
    const file_object_authenticator_t *auth = file_object_crypto_manifest_authenticator(provider);
    assert(auth != NULL);
    assert(auth->start(auth->ctx) == PICOKEYS_OK);
    assert(auth->update(auth->ctx, data, len / 2) == PICOKEYS_OK);
    assert(auth->update(auth->ctx, data + len / 2, len - len / 2) == PICOKEYS_OK);
    assert(auth->finish(auth->ctx, tag) == PICOKEYS_OK);
}

static void test_initialization(void) {
    file_object_crypto_provider_t provider;
    test_root_context_t root;
    test_root_reset(&root, 1);
    file_object_crypto_provider_config_t config = {
        .ctx = &root,
        .namespace_id = 0,
        .load_root = test_root_load
    };

    assert(file_object_crypto_provider_init(NULL, &config) == PICOKEYS_ERR_NULL_PARAM);
    assert(file_object_crypto_provider_init(&provider, &config) == PICOKEYS_ERR_NULL_PARAM);
    config.namespace_id = TEST_NAMESPACE_A;
    config.load_root = NULL;
    assert(file_object_crypto_provider_init(&provider, &config) == PICOKEYS_ERR_NULL_PARAM);
}

static void test_manifest_authentication(void) {
    static const uint8_t data[] = { 1, 2, 3, 4, 5 };
    file_object_crypto_provider_t provider_a;
    file_object_crypto_provider_t provider_b;
    test_root_context_t root;
    test_root_reset(&root, 1);
    test_provider_init(&provider_a, &root, TEST_NAMESPACE_A);
    test_provider_init(&provider_b, &root, TEST_NAMESPACE_B);
    uint8_t first[FILE_OBJECT_AUTH_TAG_SIZE];
    uint8_t second[FILE_OBJECT_AUTH_TAG_SIZE];
    uint8_t other_namespace[FILE_OBJECT_AUTH_TAG_SIZE];

    test_manifest_tag(&provider_a, data, sizeof(data), first);
    test_manifest_tag(&provider_a, data, sizeof(data), second);
    test_manifest_tag(&provider_b, data, sizeof(data), other_namespace);
    assert(memcmp(first, second, sizeof(first)) == 0);
    assert(memcmp(first, other_namespace, sizeof(first)) != 0);

    root.public_available = false;
    const file_object_authenticator_t *auth = file_object_crypto_manifest_authenticator(&provider_a);
    assert(auth->start(auth->ctx) == PICOKEYS_NO_LOGIN);

    file_object_crypto_provider_deinit(&provider_a);
    file_object_crypto_provider_deinit(&provider_b);
    assert(file_object_crypto_manifest_authenticator(&provider_a) == NULL);
}

static void test_authenticated_public_record(void) {
    static const uint8_t plaintext[] = { 0x10, 0x20, 0x30, 0x40, 0x50 };
    file_object_crypto_provider_t provider;
    test_root_context_t root;
    test_root_reset(&root, 1);
    test_provider_init(&provider, &root, TEST_NAMESPACE_A);
    const file_object_record_protector_t *protector = file_object_crypto_record_protector(&provider);
    file_object_record_identity_t identity = test_identity(TEST_NAMESPACE_A, FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC);
    uint8_t aad[FILE_OBJECT_RECORD_AAD_SIZE];
    uint8_t nonce[FILE_OBJECT_RECORD_NONCE_SIZE];
    uint8_t stored[sizeof(plaintext)];
    uint8_t output[sizeof(plaintext)];
    uint8_t tag[FILE_OBJECT_AUTH_TAG_SIZE];

    test_aad_build(&identity, aad, nonce);
    assert(protector->seal(protector->ctx, &identity, nonce, aad, plaintext, sizeof(plaintext), stored, tag) == PICOKEYS_OK);
    assert(memcmp(stored, plaintext, sizeof(plaintext)) == 0);
    assert(protector->unseal(protector->ctx, &identity, nonce, aad, stored, sizeof(stored), tag, output) == PICOKEYS_OK);
    assert(memcmp(output, plaintext, sizeof(plaintext)) == 0);

    root.available = false;
    assert(protector->unseal(protector->ctx, &identity, nonce, aad, stored, sizeof(stored), tag, output) == PICOKEYS_OK);

    stored[0] ^= 0x01;
    assert(protector->unseal(protector->ctx, &identity, nonce, aad, stored, sizeof(stored), tag, output) == PICOKEYS_WRONG_SIGNATURE);

    file_object_crypto_provider_deinit(&provider);
}

static void test_aead_secret_record(void) {
    static const uint8_t plaintext[] = { 0x60, 0x70, 0x80, 0x90, 0xa0 };
    file_object_crypto_provider_t provider;
    file_object_crypto_provider_t wrong_provider;
    test_root_context_t root;
    test_root_context_t wrong_root;
    test_root_reset(&root, 1);
    test_root_reset(&wrong_root, 0x80);
    test_provider_init(&provider, &root, TEST_NAMESPACE_A);
    test_provider_init(&wrong_provider, &wrong_root, TEST_NAMESPACE_A);
    const file_object_record_protector_t *protector = file_object_crypto_record_protector(&provider);
    const file_object_record_protector_t *wrong_protector = file_object_crypto_record_protector(&wrong_provider);
    file_object_record_identity_t identity = test_identity(TEST_NAMESPACE_A, FILE_OBJECT_PROTECTION_AEAD_SECRET);
    uint8_t aad[FILE_OBJECT_RECORD_AAD_SIZE];
    uint8_t nonce[FILE_OBJECT_RECORD_NONCE_SIZE];
    uint8_t stored[sizeof(plaintext)];
    uint8_t output[sizeof(plaintext)];
    uint8_t tag[FILE_OBJECT_AUTH_TAG_SIZE];

    test_aad_build(&identity, aad, nonce);
    assert(protector->seal(protector->ctx, &identity, nonce, aad, plaintext, sizeof(plaintext), stored, tag) == PICOKEYS_OK);
    assert(memcmp(stored, plaintext, sizeof(plaintext)) != 0);
    assert(protector->unseal(protector->ctx, &identity, nonce, aad, stored, sizeof(stored), tag, output) == PICOKEYS_OK);
    assert(memcmp(output, plaintext, sizeof(plaintext)) == 0);
    assert(wrong_protector->unseal(wrong_protector->ctx, &identity, nonce, aad, stored, sizeof(stored), tag, output) == PICOKEYS_WRONG_SIGNATURE);
    for (size_t i = 0; i < sizeof(output); i++) {
        assert(output[i] == 0);
    }

    stored[0] ^= 0x01;
    memset(output, 0xa5, sizeof(output));
    assert(protector->unseal(protector->ctx, &identity, nonce, aad, stored, sizeof(stored), tag, output) == PICOKEYS_WRONG_SIGNATURE);
    for (size_t i = 0; i < sizeof(output); i++) {
        assert(output[i] == 0);
    }
    stored[0] ^= 0x01;

    aad[TEST_AAD_CONTAINER_ID_OFFSET] ^= 0x01;
    assert(protector->unseal(protector->ctx, &identity, nonce, aad, stored, sizeof(stored), tag, output) == PICOKEYS_WRONG_DATA);
    aad[TEST_AAD_CONTAINER_ID_OFFSET] ^= 0x01;

    tag[0] ^= 0x01;
    memset(output, 0xa5, sizeof(output));
    assert(protector->unseal(protector->ctx, &identity, nonce, aad, stored, sizeof(stored), tag, output) == PICOKEYS_WRONG_SIGNATURE);
    for (size_t i = 0; i < sizeof(output); i++) {
        assert(output[i] == 0);
    }
    tag[0] ^= 0x01;

    identity.container_id++;
    test_aad_build(&identity, aad, nonce);
    assert(protector->unseal(protector->ctx, &identity, nonce, aad, stored, sizeof(stored), tag, output) == PICOKEYS_WRONG_SIGNATURE);

    identity = test_identity(TEST_NAMESPACE_A, FILE_OBJECT_PROTECTION_AEAD_SECRET);
    identity.policy_hash[0] ^= 0x01;
    test_aad_build(&identity, aad, nonce);
    assert(protector->unseal(protector->ctx, &identity, nonce, aad, stored, sizeof(stored), tag, output) == PICOKEYS_WRONG_SIGNATURE);

    identity = test_identity(TEST_NAMESPACE_A, FILE_OBJECT_PROTECTION_AEAD_SECRET);
    identity.key_domain = TEST_MAX_KEY_DOMAINS;
    test_aad_build(&identity, aad, nonce);
    assert(protector->seal(protector->ctx, &identity, nonce, aad, plaintext, sizeof(plaintext), stored, tag) == PICOKEYS_WRONG_DATA);

    identity = test_identity(TEST_NAMESPACE_A, FILE_OBJECT_PROTECTION_AEAD_SECRET);
    test_aad_build(&identity, aad, nonce);
    root.available = false;
    assert(protector->seal(protector->ctx, &identity, nonce, aad, plaintext, sizeof(plaintext), stored, tag) == PICOKEYS_NO_LOGIN);

    file_object_crypto_provider_deinit(&provider);
    file_object_crypto_provider_deinit(&wrong_provider);
}

static void test_empty_internal_record(void) {
    file_object_crypto_provider_t provider;
    test_root_context_t root;
    test_root_reset(&root, 1);
    test_provider_init(&provider, &root, TEST_NAMESPACE_A);
    const file_object_record_protector_t *protector = file_object_crypto_record_protector(&provider);
    file_object_record_identity_t identity = test_identity(TEST_NAMESPACE_A, FILE_OBJECT_PROTECTION_FIRMWARE_INTERNAL);
    uint8_t aad[FILE_OBJECT_RECORD_AAD_SIZE];
    uint8_t nonce[FILE_OBJECT_RECORD_NONCE_SIZE];
    uint8_t stored = 0;
    uint8_t tag[FILE_OBJECT_AUTH_TAG_SIZE];

    identity.logical_size = 0;
    test_aad_build(&identity, aad, nonce);
    assert(protector->seal(protector->ctx, &identity, nonce, aad, NULL, 0, &stored, tag) == PICOKEYS_OK);
    assert(protector->unseal(protector->ctx, &identity, nonce, aad, &stored, 0, tag, NULL) == PICOKEYS_OK);

    file_object_crypto_provider_deinit(&provider);
}

int main(void) {
    test_initialization();
    test_manifest_authentication();
    test_authenticated_public_record();
    test_aead_secret_record();
    test_empty_internal_record();
    puts("object_crypto_provider_test: OK");
    return 0;
}
