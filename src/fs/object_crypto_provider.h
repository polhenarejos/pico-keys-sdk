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

#ifndef _OBJECT_CRYPTO_PROVIDER_H_
#define _OBJECT_CRYPTO_PROVIDER_H_

#include "object_container.h"

#include <mbedtls/md.h>

#define FILE_OBJECT_CRYPTO_ROOT_KEY_SIZE 32u

/* The provider zeroizes the root buffer after every callback invocation. */
typedef int (*file_object_crypto_root_load_t)(void *ctx, uint8_t root[FILE_OBJECT_CRYPTO_ROOT_KEY_SIZE]);
/* This optional callback applies application-specific constraints after namespace validation. */
typedef bool (*file_object_crypto_identity_valid_t)(void *ctx, const file_object_record_identity_t *identity);

typedef struct file_object_crypto_provider_config {
    void *ctx;
    uint16_t namespace_id;
    file_object_crypto_root_load_t load_root;
    /* Optional device-bound root for manifests and authenticated-public records. Falls back to load_root. */
    file_object_crypto_root_load_t load_public_root;
    file_object_crypto_identity_valid_t identity_valid;
} file_object_crypto_provider_config_t;

/* One manifest authentication may be active per instance. Instances must not be copied after initialization. */
typedef struct file_object_crypto_provider {
    file_object_crypto_provider_config_t config;
    file_object_authenticator_t manifest_authenticator;
    file_object_record_protector_t record_protector;
    mbedtls_md_context_t manifest_md;
    bool manifest_active;
    bool initialized;
} file_object_crypto_provider_t;

int file_object_crypto_provider_init(file_object_crypto_provider_t *provider, const file_object_crypto_provider_config_t *config);
void file_object_crypto_provider_deinit(file_object_crypto_provider_t *provider);
const file_object_authenticator_t *file_object_crypto_manifest_authenticator(file_object_crypto_provider_t *provider);
const file_object_record_protector_t *file_object_crypto_record_protector(file_object_crypto_provider_t *provider);

#endif // _OBJECT_CRYPTO_PROVIDER_H_
