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
#include "otp_platform.h"

#if defined(MACOS_APP) && MACOS_APP
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdio.h>
#include <string.h>

#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"
#include "mbedtls/sha256.h"

#define CF_SAFE_RELEASE(x) do { if ((x) != NULL) CFRelease(x); } while (0)
#define SE_KEY_TAG "com.picokeys.novus.se.key"
#define LOCAL_KEY_TAG "com.picokeys.novus.local.ecdh.key"

static int sec_err(const char *ctx, OSStatus st) {
    fprintf(stderr, "[macos-se] %s failed: OSStatus=%d\n", ctx, (int)st);
    return -1;
}

static int derive_secp256k1_privkey_from_secret(const uint8_t *secret, size_t secret_len, uint8_t out_key32[32]) {
    int rc = -1;
    uint8_t digest[32];
    const uint8_t label[] = "pico-novus/se-ecdh-to-k1-v1";
    mbedtls_ecp_group grp;
    mbedtls_mpi x, n_minus_1;

    if (!secret || secret_len == 0 || !out_key32) {
        return -1;
    }

    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);
    mbedtls_sha256_update(&sha, label, sizeof(label) - 1);
    mbedtls_sha256_update(&sha, secret, secret_len);
    mbedtls_sha256_finish(&sha, digest);
    mbedtls_sha256_free(&sha);

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&x);
    mbedtls_mpi_init(&n_minus_1);

    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1) != 0) {
        goto cleanup;
    }
    if (mbedtls_mpi_read_binary(&x, digest, sizeof(digest)) != 0) {
        goto cleanup;
    }
    if (mbedtls_mpi_copy(&n_minus_1, &grp.N) != 0) {
        goto cleanup;
    }
    if (mbedtls_mpi_sub_int(&n_minus_1, &n_minus_1, 1) != 0) {
        goto cleanup;
    }
    if (mbedtls_mpi_mod_mpi(&x, &x, &n_minus_1) != 0) {
        goto cleanup;
    }
    if (mbedtls_mpi_add_int(&x, &x, 1) != 0) {
        goto cleanup;
    }
    if (mbedtls_mpi_write_binary(&x, out_key32, 32) != 0) {
        goto cleanup;
    }

    rc = 0;

cleanup:
    mbedtls_mpi_free(&n_minus_1);
    mbedtls_mpi_free(&x);
    mbedtls_ecp_group_free(&grp);
    return rc;
}

static int load_or_create_p256_key(const char *tag_str, bool in_secure_enclave, SecKeyRef *out_private_key) {
    SecKeyRef private_key = NULL;
    CFDataRef tag = NULL;
    CFDictionaryRef find_query = NULL;
    CFDictionaryRef priv_attrs = NULL;
    CFNumberRef key_size_num = NULL;
    CFDictionaryRef attrs = NULL;
    CFErrorRef err = NULL;
    OSStatus st;
    int rc = -1;

    if (!tag_str || !out_private_key) {
        return -1;
    }

    *out_private_key = NULL;
    tag = CFDataCreate(NULL, (const UInt8 *)tag_str, (CFIndex)strlen(tag_str));
    if (!tag) {
        fprintf(stderr, "[macos-se] CFDataCreate(tag) failed\n");
        goto cleanup;
    }

    const void *find_keys[] = { kSecClass, kSecAttrApplicationTag, kSecAttrKeyType, kSecReturnRef };
    const void *find_vals[] = { kSecClassKey, tag, kSecAttrKeyTypeECSECPrimeRandom, kCFBooleanTrue };
    find_query = CFDictionaryCreate(NULL, find_keys, find_vals, 4, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (!find_query) {
        fprintf(stderr, "[macos-se] CFDictionaryCreate(find_query) failed\n");
        goto cleanup;
    }

    st = SecItemCopyMatching(find_query, (CFTypeRef *)&private_key);
    if (st == errSecItemNotFound) {
        const void *priv_keys[] = { kSecAttrIsPermanent, kSecAttrApplicationTag };
        const void *priv_vals[] = { kCFBooleanTrue, tag };
        priv_attrs = CFDictionaryCreate(NULL, priv_keys, priv_vals, 2, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        if (!priv_attrs) {
            fprintf(stderr, "[macos-se] CFDictionaryCreate(priv_attrs) failed\n");
            goto cleanup;
        }

        int key_size = 256;
        key_size_num = CFNumberCreate(NULL, kCFNumberIntType, &key_size);
        if (!key_size_num) {
            fprintf(stderr, "[macos-se] CFNumberCreate(key_size) failed\n");
            goto cleanup;
        }

        if (in_secure_enclave) {
            const void *keys[] = { kSecAttrKeyType, kSecAttrKeySizeInBits, kSecAttrTokenID, kSecPrivateKeyAttrs };
            const void *vals[] = { kSecAttrKeyTypeECSECPrimeRandom, key_size_num, kSecAttrTokenIDSecureEnclave, priv_attrs };
            attrs = CFDictionaryCreate(NULL, keys, vals, 4, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        } else {
            const void *keys[] = { kSecAttrKeyType, kSecAttrKeySizeInBits, kSecPrivateKeyAttrs };
            const void *vals[] = { kSecAttrKeyTypeECSECPrimeRandom, key_size_num, priv_attrs };
            attrs = CFDictionaryCreate(NULL, keys, vals, 3, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        }
        if (!attrs) {
            fprintf(stderr, "[macos-se] CFDictionaryCreate(attrs) failed\n");
            goto cleanup;
        }

        private_key = SecKeyCreateRandomKey(attrs, &err);
        if (!private_key) {
            fprintf(stderr, "[macos-se] SecKeyCreateRandomKey failed\n");
            if (err) {
                CFShow(err);
            }
            goto cleanup;
        }
        printf("[macos-se] Created key '%s'%s\n", tag_str, in_secure_enclave ? " in Secure Enclave" : "");
    } else if (st != errSecSuccess) {
        sec_err("SecItemCopyMatching", st);
        goto cleanup;
    } else {
        printf("[macos-se] Using existing key '%s'\n", tag_str);
    }

    *out_private_key = private_key;
    private_key = NULL;
    rc = 0;

cleanup:
    if (err) {
        CFRelease(err);
    }
    CF_SAFE_RELEASE(attrs);
    CF_SAFE_RELEASE(key_size_num);
    CF_SAFE_RELEASE(priv_attrs);
    CF_SAFE_RELEASE(find_query);
    CF_SAFE_RELEASE(tag);
    CF_SAFE_RELEASE(private_key);
    return rc;
}

static int macos_se_vault_load_or_create_key2(uint8_t out_key32[32]) {
    int rc = -1;
    SecKeyRef se_private_key = NULL;
    SecKeyRef local_private_key = NULL;
    SecKeyRef local_public_key = NULL;
    CFDataRef shared_secret = NULL;
    CFDictionaryRef ecdh_params = NULL;
    CFErrorRef err = NULL;

    if (load_or_create_p256_key(SE_KEY_TAG, true, &se_private_key) != 0) {
        goto cleanup;
    }
    if (load_or_create_p256_key(LOCAL_KEY_TAG, false, &local_private_key) != 0) {
        goto cleanup;
    }

    local_public_key = SecKeyCopyPublicKey(local_private_key);
    if (!local_public_key) {
        fprintf(stderr, "[macos-se] SecKeyCopyPublicKey(local_private_key) failed\n");
        goto cleanup;
    }

    ecdh_params = CFDictionaryCreate(NULL, NULL, NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (!ecdh_params) {
        fprintf(stderr, "[macos-se] CFDictionaryCreate(ecdh_params) failed\n");
        goto cleanup;
    }

    shared_secret = SecKeyCopyKeyExchangeResult(se_private_key, kSecKeyAlgorithmECDHKeyExchangeStandard, local_public_key, ecdh_params, &err);
    if (!shared_secret) {
        fprintf(stderr, "[macos-se] SecKeyCopyKeyExchangeResult failed\n");
        if (err) {
            CFShow(err);
        }
        goto cleanup;
    }

    if (derive_secp256k1_privkey_from_secret(CFDataGetBytePtr(shared_secret), (size_t)CFDataGetLength(shared_secret), out_key32) != 0) {
        fprintf(stderr, "[macos-se] failed deriving secp256k1 private key from ECDH secret\n");
        goto cleanup;
    }
    rc = 0;

cleanup:
    if (err) {
        CFRelease(err);
    }
    CF_SAFE_RELEASE(ecdh_params);
    CF_SAFE_RELEASE(shared_secret);
    CF_SAFE_RELEASE(local_public_key);
    CF_SAFE_RELEASE(local_private_key);
    CF_SAFE_RELEASE(se_private_key);
    return rc;
}
#endif

int otp_platform_enable_secure_boot(uint8_t bootkey, bool secure_lock) {
    (void)bootkey;
    (void)secure_lock;
    return PICOKEYS_OK;
}

bool otp_platform_is_secure_boot_enabled(uint8_t *bootkey) {
    (void)bootkey;
    return true;
}

bool otp_platform_is_secure_boot_locked(void) {
    return false;
}

void otp_platform_init(const uint8_t **otp_key_1_out, const uint8_t **otp_key_2_out) {
    static uint8_t _otp1[32] = {0};
    static uint8_t _otp2[32] = {0};

    memset(_otp1, 0xAC, sizeof(_otp1));
    memset(_otp2, 0xBE, sizeof(_otp2));

#if defined(MACOS_APP) && MACOS_APP
    if (macos_se_vault_load_or_create_key2(_otp2) != 0) {
        printf("Warning: failed to load MACOS_APP Secure Enclave key; using dummy otp_key_2\n");
    }
    DEBUG_DATA(_otp2, 32);
#endif
    *otp_key_1_out = _otp1;
    *otp_key_2_out = _otp2;
}
