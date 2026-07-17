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

#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/platform_util.h>

#define FILE_OBJECT_CRYPTO_HMAC_SIZE 32u

#define FILE_OBJECT_CRYPTO_AAD_NAMESPACE_OFFSET 5u
#define FILE_OBJECT_CRYPTO_AAD_KIND_OFFSET 7u
#define FILE_OBJECT_CRYPTO_AAD_CONTAINER_ID_OFFSET 9u
#define FILE_OBJECT_CRYPTO_AAD_TYPE_OFFSET 13u
#define FILE_OBJECT_CRYPTO_AAD_TAG_OFFSET 15u
#define FILE_OBJECT_CRYPTO_AAD_GENERATION_OFFSET 17u
#define FILE_OBJECT_CRYPTO_AAD_LOGICAL_SIZE_OFFSET 21u
#define FILE_OBJECT_CRYPTO_AAD_POLICY_ID_OFFSET 25u
#define FILE_OBJECT_CRYPTO_AAD_POLICY_HASH_OFFSET 27u
#define FILE_OBJECT_CRYPTO_AAD_KEY_DOMAIN_OFFSET 43u
#define FILE_OBJECT_CRYPTO_AAD_PROTECTION_OFFSET 44u
#define FILE_OBJECT_CRYPTO_AAD_FLAGS_OFFSET 45u
#define FILE_OBJECT_CRYPTO_AAD_RECORD_ID_OFFSET 47u

static const uint8_t file_object_crypto_record_magic[4] = { 'P', 'K', 'O', 'R' };
static const uint8_t file_object_crypto_domain_label[] = "PKOC/domain/v1";
static const uint8_t file_object_crypto_key_label[] = "PKOC/object/v1";
static const uint8_t file_object_crypto_manifest_label[] = "PKOC/manifest/v1";

static const mbedtls_md_info_t *file_object_crypto_sha256(void) {
    return mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
}

static bool file_object_crypto_provider_valid(const file_object_crypto_provider_t *provider) {
    return provider && provider->initialized && provider->config.namespace_id != 0 && provider->config.load_root;
}

static int file_object_crypto_load_root(file_object_crypto_provider_t *provider, uint8_t root[FILE_OBJECT_CRYPTO_ROOT_KEY_SIZE]) {
    int r = provider->config.load_root(provider->config.ctx, root);
    if (r != PICOKEYS_OK) {
        mbedtls_platform_zeroize(root, FILE_OBJECT_CRYPTO_ROOT_KEY_SIZE);
    }
    return r;
}

static int file_object_crypto_derive_manifest_key(file_object_crypto_provider_t *provider, uint8_t key[FILE_OBJECT_CRYPTO_ROOT_KEY_SIZE]) {
    uint8_t root[FILE_OBJECT_CRYPTO_ROOT_KEY_SIZE] = { 0 };
    uint8_t info[sizeof(uint16_t) + sizeof(file_object_crypto_manifest_label) - 1];
    put_uint16_be(provider->config.namespace_id, info);
    memcpy(info + sizeof(uint16_t), file_object_crypto_manifest_label, sizeof(file_object_crypto_manifest_label) - 1);

    int r = file_object_crypto_load_root(provider, root);
    if (r == PICOKEYS_OK && mbedtls_hkdf(file_object_crypto_sha256(), NULL, 0, root, sizeof(root), info, sizeof(info), key, FILE_OBJECT_CRYPTO_ROOT_KEY_SIZE) != 0) {
        r = PICOKEYS_EXEC_ERROR;
    }
    mbedtls_platform_zeroize(root, sizeof(root));
    mbedtls_platform_zeroize(info, sizeof(info));
    return r;
}

static int file_object_crypto_derive_record_key(file_object_crypto_provider_t *provider, const file_object_record_identity_t *identity, const uint8_t aad[FILE_OBJECT_RECORD_AAD_SIZE], uint8_t key[FILE_OBJECT_CRYPTO_ROOT_KEY_SIZE]) {
    uint8_t root[FILE_OBJECT_CRYPTO_ROOT_KEY_SIZE] = { 0 };
    uint8_t domain_key[FILE_OBJECT_CRYPTO_ROOT_KEY_SIZE] = { 0 };
    uint8_t domain_info[sizeof(uint16_t) + sizeof(uint8_t) + sizeof(file_object_crypto_domain_label) - 1];
    uint8_t object_info[sizeof(file_object_crypto_key_label) - 1 + FILE_OBJECT_RECORD_AAD_SIZE];

    put_uint16_be(identity->namespace_id, domain_info);
    domain_info[sizeof(uint16_t)] = identity->key_domain;
    memcpy(domain_info + sizeof(uint16_t) + sizeof(uint8_t), file_object_crypto_domain_label, sizeof(file_object_crypto_domain_label) - 1);
    memcpy(object_info, file_object_crypto_key_label, sizeof(file_object_crypto_key_label) - 1);
    memcpy(object_info + sizeof(file_object_crypto_key_label) - 1, aad, FILE_OBJECT_RECORD_AAD_SIZE);

    int r = file_object_crypto_load_root(provider, root);
    if (r == PICOKEYS_OK && mbedtls_hkdf(file_object_crypto_sha256(), NULL, 0, root, sizeof(root), domain_info, sizeof(domain_info), domain_key, sizeof(domain_key)) != 0) {
        r = PICOKEYS_EXEC_ERROR;
    }
    if (r == PICOKEYS_OK && mbedtls_hkdf(file_object_crypto_sha256(), NULL, 0, domain_key, sizeof(domain_key), object_info, sizeof(object_info), key, FILE_OBJECT_CRYPTO_ROOT_KEY_SIZE) != 0) {
        r = PICOKEYS_EXEC_ERROR;
    }
    mbedtls_platform_zeroize(root, sizeof(root));
    mbedtls_platform_zeroize(domain_key, sizeof(domain_key));
    mbedtls_platform_zeroize(domain_info, sizeof(domain_info));
    mbedtls_platform_zeroize(object_info, sizeof(object_info));
    return r;
}

static bool file_object_crypto_identity_valid(file_object_crypto_provider_t *provider, const file_object_record_identity_t *identity, const uint8_t nonce[FILE_OBJECT_RECORD_NONCE_SIZE], const uint8_t aad[FILE_OBJECT_RECORD_AAD_SIZE]) {
    if (!file_object_crypto_provider_valid(provider) || !identity || !nonce || !aad || identity->namespace_id != provider->config.namespace_id) {
        return false;
    }
    if (identity->generation == 0 || identity->record_id == 0 || identity->protection < FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC || identity->protection > FILE_OBJECT_PROTECTION_FIRMWARE_INTERNAL || (identity->flags & ~FILE_OBJECT_FLAG_MASK) != 0 || (identity->flags & FILE_OBJECT_FLAG_INLINE) != 0) {
        return false;
    }
    if (provider->config.identity_valid && !provider->config.identity_valid(provider->config.ctx, identity)) {
        return false;
    }
    if (memcmp(aad, file_object_crypto_record_magic, sizeof(file_object_crypto_record_magic)) != 0 || aad[4] != FILE_OBJECT_RECORD_FORMAT_VERSION) {
        return false;
    }
    if (get_uint16_be(aad + FILE_OBJECT_CRYPTO_AAD_NAMESPACE_OFFSET) != identity->namespace_id
        || get_uint16_be(aad + FILE_OBJECT_CRYPTO_AAD_KIND_OFFSET) != identity->container_kind
        || get_uint32_be(aad + FILE_OBJECT_CRYPTO_AAD_CONTAINER_ID_OFFSET) != identity->container_id
        || get_uint16_be(aad + FILE_OBJECT_CRYPTO_AAD_TYPE_OFFSET) != identity->object_type
        || get_uint16_be(aad + FILE_OBJECT_CRYPTO_AAD_TAG_OFFSET) != identity->object_tag
        || get_uint32_be(aad + FILE_OBJECT_CRYPTO_AAD_GENERATION_OFFSET) != identity->generation
        || get_uint32_be(aad + FILE_OBJECT_CRYPTO_AAD_LOGICAL_SIZE_OFFSET) != identity->logical_size
        || get_uint16_be(aad + FILE_OBJECT_CRYPTO_AAD_POLICY_ID_OFFSET) != identity->policy_id
        || memcmp(aad + FILE_OBJECT_CRYPTO_AAD_POLICY_HASH_OFFSET, identity->policy_hash, FILE_OBJECT_POLICY_HASH_SIZE) != 0
        || aad[FILE_OBJECT_CRYPTO_AAD_KEY_DOMAIN_OFFSET] != identity->key_domain
        || aad[FILE_OBJECT_CRYPTO_AAD_PROTECTION_OFFSET] != identity->protection
        || get_uint16_be(aad + FILE_OBJECT_CRYPTO_AAD_FLAGS_OFFSET) != identity->flags
        || get_uint64_be(aad + FILE_OBJECT_CRYPTO_AAD_RECORD_ID_OFFSET) != identity->record_id) {
        return false;
    }
    return get_uint64_be(nonce) == identity->record_id && get_uint32_be(nonce + sizeof(uint64_t)) == identity->generation;
}

static bool file_object_crypto_tag_equal(const uint8_t *left, const uint8_t *right) {
    uint8_t difference = 0;
    for (size_t i = 0; i < FILE_OBJECT_AUTH_TAG_SIZE; i++) {
        difference |= left[i] ^ right[i];
    }
    return difference == 0;
}

static int file_object_crypto_hmac(const uint8_t key[FILE_OBJECT_CRYPTO_ROOT_KEY_SIZE], const uint8_t nonce[FILE_OBJECT_RECORD_NONCE_SIZE], const uint8_t aad[FILE_OBJECT_RECORD_AAD_SIZE], const uint8_t *stored, size_t len, uint8_t tag[FILE_OBJECT_AUTH_TAG_SIZE]) {
    mbedtls_md_context_t md;
    mbedtls_md_init(&md);
    uint8_t full_tag[FILE_OBJECT_CRYPTO_HMAC_SIZE] = { 0 };
    int r = mbedtls_md_setup(&md, file_object_crypto_sha256(), 1);
    if (r == 0) {
        r = mbedtls_md_hmac_starts(&md, key, FILE_OBJECT_CRYPTO_ROOT_KEY_SIZE);
    }
    if (r == 0) {
        r = mbedtls_md_hmac_update(&md, aad, FILE_OBJECT_RECORD_AAD_SIZE);
    }
    if (r == 0) {
        r = mbedtls_md_hmac_update(&md, nonce, FILE_OBJECT_RECORD_NONCE_SIZE);
    }
    if (r == 0 && len > 0) {
        r = mbedtls_md_hmac_update(&md, stored, len);
    }
    if (r == 0) {
        r = mbedtls_md_hmac_finish(&md, full_tag);
    }
    if (r == 0) {
        memcpy(tag, full_tag, FILE_OBJECT_AUTH_TAG_SIZE);
    }
    mbedtls_platform_zeroize(full_tag, sizeof(full_tag));
    mbedtls_md_free(&md);
    return r == 0 ? PICOKEYS_OK : PICOKEYS_EXEC_ERROR;
}

static int file_object_crypto_record_seal(void *ctx, const file_object_record_identity_t *identity, const uint8_t nonce[FILE_OBJECT_RECORD_NONCE_SIZE], const uint8_t aad[FILE_OBJECT_RECORD_AAD_SIZE], const uint8_t *plaintext, size_t len, uint8_t *stored, uint8_t tag[FILE_OBJECT_AUTH_TAG_SIZE]) {
    file_object_crypto_provider_t *provider = (file_object_crypto_provider_t *)ctx;
    if (!file_object_crypto_identity_valid(provider, identity, nonce, aad) || (!plaintext && len > 0) || !stored || !tag) {
        return PICOKEYS_WRONG_DATA;
    }

    uint8_t key[FILE_OBJECT_CRYPTO_ROOT_KEY_SIZE] = { 0 };
    int r = file_object_crypto_derive_record_key(provider, identity, aad, key);
    if (r == PICOKEYS_OK && identity->protection == FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC) {
        if (len > 0) {
            memmove(stored, plaintext, len);
        }
        r = file_object_crypto_hmac(key, nonce, aad, stored, len, tag);
    }
    else if (r == PICOKEYS_OK) {
        mbedtls_gcm_context gcm;
        mbedtls_gcm_init(&gcm);
        uint8_t empty_input = 0;
        uint8_t empty_output = 0;
        const uint8_t *gcm_input = len > 0 ? plaintext : &empty_input;
        uint8_t *gcm_output = len > 0 ? stored : &empty_output;
        int crypto_result = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, FILE_OBJECT_CRYPTO_ROOT_KEY_SIZE * 8u);
        if (crypto_result == 0) {
            crypto_result = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, len, nonce, FILE_OBJECT_RECORD_NONCE_SIZE, aad, FILE_OBJECT_RECORD_AAD_SIZE, gcm_input, gcm_output, FILE_OBJECT_AUTH_TAG_SIZE, tag);
        }
        mbedtls_gcm_free(&gcm);
        r = crypto_result == 0 ? PICOKEYS_OK : PICOKEYS_EXEC_ERROR;
    }
    mbedtls_platform_zeroize(key, sizeof(key));
    return r;
}

static int file_object_crypto_record_unseal(void *ctx, const file_object_record_identity_t *identity, const uint8_t nonce[FILE_OBJECT_RECORD_NONCE_SIZE], const uint8_t aad[FILE_OBJECT_RECORD_AAD_SIZE], const uint8_t *stored, size_t len, const uint8_t tag[FILE_OBJECT_AUTH_TAG_SIZE], uint8_t *plaintext) {
    file_object_crypto_provider_t *provider = (file_object_crypto_provider_t *)ctx;
    if (!file_object_crypto_identity_valid(provider, identity, nonce, aad) || (!stored && len > 0) || !tag || (!plaintext && len > 0)) {
        return PICOKEYS_WRONG_DATA;
    }

    uint8_t key[FILE_OBJECT_CRYPTO_ROOT_KEY_SIZE] = { 0 };
    int r = file_object_crypto_derive_record_key(provider, identity, aad, key);
    if (r == PICOKEYS_OK && identity->protection == FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC) {
        uint8_t calculated_tag[FILE_OBJECT_AUTH_TAG_SIZE] = { 0 };
        r = file_object_crypto_hmac(key, nonce, aad, stored, len, calculated_tag);
        if (r == PICOKEYS_OK && !file_object_crypto_tag_equal(calculated_tag, tag)) {
            r = PICOKEYS_WRONG_SIGNATURE;
        }
        if (r == PICOKEYS_OK && len > 0) {
            memmove(plaintext, stored, len);
        }
        mbedtls_platform_zeroize(calculated_tag, sizeof(calculated_tag));
    }
    else if (r == PICOKEYS_OK) {
        mbedtls_gcm_context gcm;
        mbedtls_gcm_init(&gcm);
        uint8_t empty_input = 0;
        uint8_t empty_output = 0;
        const uint8_t *gcm_input = len > 0 ? stored : &empty_input;
        uint8_t *gcm_output = len > 0 ? plaintext : &empty_output;
        int crypto_result = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, FILE_OBJECT_CRYPTO_ROOT_KEY_SIZE * 8u);
        if (crypto_result == 0) {
            crypto_result = mbedtls_gcm_auth_decrypt(&gcm, len, nonce, FILE_OBJECT_RECORD_NONCE_SIZE, aad, FILE_OBJECT_RECORD_AAD_SIZE, tag, FILE_OBJECT_AUTH_TAG_SIZE, gcm_input, gcm_output);
            r = crypto_result == 0 ? PICOKEYS_OK : PICOKEYS_WRONG_SIGNATURE;
        }
        else {
            r = PICOKEYS_EXEC_ERROR;
        }
        mbedtls_gcm_free(&gcm);
    }
    if (r != PICOKEYS_OK && plaintext && len > 0) {
        mbedtls_platform_zeroize(plaintext, len);
    }
    mbedtls_platform_zeroize(key, sizeof(key));
    return r;
}

static void file_object_crypto_auth_abort(void *ctx) {
    file_object_crypto_provider_t *provider = (file_object_crypto_provider_t *)ctx;
    if (!provider || !provider->initialized) {
        return;
    }
    mbedtls_md_free(&provider->manifest_md);
    mbedtls_md_init(&provider->manifest_md);
    provider->manifest_active = false;
}

static int file_object_crypto_auth_start(void *ctx) {
    file_object_crypto_provider_t *provider = (file_object_crypto_provider_t *)ctx;
    if (!file_object_crypto_provider_valid(provider)) {
        return PICOKEYS_WRONG_DATA;
    }
    file_object_crypto_auth_abort(provider);

    uint8_t key[FILE_OBJECT_CRYPTO_ROOT_KEY_SIZE] = { 0 };
    int r = file_object_crypto_derive_manifest_key(provider, key);
    if (r == PICOKEYS_OK && (mbedtls_md_setup(&provider->manifest_md, file_object_crypto_sha256(), 1) != 0 || mbedtls_md_hmac_starts(&provider->manifest_md, key, sizeof(key)) != 0)) {
        r = PICOKEYS_EXEC_ERROR;
    }
    mbedtls_platform_zeroize(key, sizeof(key));
    if (r != PICOKEYS_OK) {
        file_object_crypto_auth_abort(provider);
        return r;
    }
    provider->manifest_active = true;
    return PICOKEYS_OK;
}

static int file_object_crypto_auth_update(void *ctx, const uint8_t *data, size_t len) {
    file_object_crypto_provider_t *provider = (file_object_crypto_provider_t *)ctx;
    if (!file_object_crypto_provider_valid(provider) || !provider->manifest_active || (!data && len > 0)) {
        return PICOKEYS_WRONG_DATA;
    }
    if (len == 0) {
        return PICOKEYS_OK;
    }
    return mbedtls_md_hmac_update(&provider->manifest_md, data, len) == 0 ? PICOKEYS_OK : PICOKEYS_EXEC_ERROR;
}

static int file_object_crypto_auth_finish(void *ctx, uint8_t tag[FILE_OBJECT_AUTH_TAG_SIZE]) {
    file_object_crypto_provider_t *provider = (file_object_crypto_provider_t *)ctx;
    if (!file_object_crypto_provider_valid(provider) || !provider->manifest_active || !tag) {
        return PICOKEYS_WRONG_DATA;
    }

    uint8_t full_tag[FILE_OBJECT_CRYPTO_HMAC_SIZE] = { 0 };
    int r = mbedtls_md_hmac_finish(&provider->manifest_md, full_tag) == 0 ? PICOKEYS_OK : PICOKEYS_EXEC_ERROR;
    if (r == PICOKEYS_OK) {
        memcpy(tag, full_tag, FILE_OBJECT_AUTH_TAG_SIZE);
    }
    mbedtls_platform_zeroize(full_tag, sizeof(full_tag));
    file_object_crypto_auth_abort(provider);
    return r;
}

int file_object_crypto_provider_init(file_object_crypto_provider_t *provider, const file_object_crypto_provider_config_t *config) {
    if (!provider || !config || config->namespace_id == 0 || !config->load_root) {
        return PICOKEYS_ERR_NULL_PARAM;
    }

    memset(provider, 0, sizeof(*provider));
    provider->config = *config;
    provider->manifest_authenticator = (file_object_authenticator_t) {
        .ctx = provider,
        .start = file_object_crypto_auth_start,
        .update = file_object_crypto_auth_update,
        .finish = file_object_crypto_auth_finish,
        .abort = file_object_crypto_auth_abort
    };
    provider->record_protector = (file_object_record_protector_t) {
        .ctx = provider,
        .seal = file_object_crypto_record_seal,
        .unseal = file_object_crypto_record_unseal
    };
    mbedtls_md_init(&provider->manifest_md);
    provider->initialized = true;
    return PICOKEYS_OK;
}

void file_object_crypto_provider_deinit(file_object_crypto_provider_t *provider) {
    if (!provider) {
        return;
    }
    if (provider->initialized) {
        file_object_crypto_auth_abort(provider);
    }
    mbedtls_platform_zeroize(provider, sizeof(*provider));
}

const file_object_authenticator_t *file_object_crypto_manifest_authenticator(file_object_crypto_provider_t *provider) {
    return file_object_crypto_provider_valid(provider) ? &provider->manifest_authenticator : NULL;
}

const file_object_record_protector_t *file_object_crypto_record_protector(file_object_crypto_provider_t *provider) {
    return file_object_crypto_provider_valid(provider) ? &provider->record_protector : NULL;
}
