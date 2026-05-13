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

#include "mbedtls/sha256.h"

#define CF_SAFE_RELEASE(x) do { if ((x) != NULL) CFRelease(x); } while (0)
#define SE_KEY_TAG "com.picokeys.novus.se.key"

static int sec_err(const char *ctx, OSStatus st) {
    fprintf(stderr, "[macos-se] %s failed: OSStatus=%d\n", ctx, (int)st);
    return -1;
}

static int macos_se_vault_load_or_create_key2(uint8_t out_key32[32]) {
    int rc = -1;
    SecKeyRef private_key = NULL;
    SecKeyRef public_key = NULL;
    CFDataRef tag = NULL;
    CFDictionaryRef find_query = NULL;
    CFDictionaryRef priv_attrs = NULL;
    CFNumberRef key_size_num = NULL;
    CFDictionaryRef attrs = NULL;
    CFDataRef pub_data = NULL;
    CFErrorRef err = NULL;
    OSStatus st;

    tag = CFDataCreate(NULL, (const UInt8 *)SE_KEY_TAG, (CFIndex)strlen(SE_KEY_TAG));
    if (!tag) {
        fprintf(stderr, "[macos-se] CFDataCreate(tag) failed\n");
        goto cleanup;
    }

    const void *find_keys[] = {
        kSecClass,
        kSecAttrApplicationTag,
        kSecAttrKeyType,
        kSecReturnRef
    };
    const void *find_vals[] = {
        kSecClassKey,
        tag,
        kSecAttrKeyTypeECSECPrimeRandom,
        kCFBooleanTrue
    };
    find_query = CFDictionaryCreate(NULL,
                                    find_keys,
                                    find_vals,
                                    4,
                                    &kCFTypeDictionaryKeyCallBacks,
                                    &kCFTypeDictionaryValueCallBacks);
    if (!find_query) {
        fprintf(stderr, "[macos-se] CFDictionaryCreate(find_query) failed\n");
        goto cleanup;
    }

    st = SecItemCopyMatching(find_query, (CFTypeRef *)&private_key);
    if (st == errSecItemNotFound) {
        const void *priv_keys[] = { kSecAttrIsPermanent, kSecAttrApplicationTag };
        const void *priv_vals[] = { kCFBooleanTrue, tag };
        priv_attrs = CFDictionaryCreate(NULL,
                                        priv_keys,
                                        priv_vals,
                                        2,
                                        &kCFTypeDictionaryKeyCallBacks,
                                        &kCFTypeDictionaryValueCallBacks);
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

        const void *keys[] = {
            kSecAttrKeyType,
            kSecAttrKeySizeInBits,
            kSecAttrTokenID,
            kSecPrivateKeyAttrs
        };
        const void *vals[] = {
            kSecAttrKeyTypeECSECPrimeRandom,
            key_size_num,
            kSecAttrTokenIDSecureEnclave,
            priv_attrs
        };
        attrs = CFDictionaryCreate(NULL,
                                   keys,
                                   vals,
                                   4,
                                   &kCFTypeDictionaryKeyCallBacks,
                                   &kCFTypeDictionaryValueCallBacks);
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
        printf("[macos-se] Created Secure Enclave key '%s'\n", SE_KEY_TAG);
    } else if (st != errSecSuccess) {
        sec_err("SecItemCopyMatching", st);
        goto cleanup;
    } else {
        printf("[macos-se] Using existing Secure Enclave key '%s'\n", SE_KEY_TAG);
    }

    public_key = SecKeyCopyPublicKey(private_key);
    if (!public_key) {
        fprintf(stderr, "[macos-se] SecKeyCopyPublicKey failed\n");
        goto cleanup;
    }

    pub_data = SecKeyCopyExternalRepresentation(public_key, &err);
    if (!pub_data) {
        fprintf(stderr, "[macos-se] SecKeyCopyExternalRepresentation failed\n");
        if (err) {
            CFShow(err);
        }
        goto cleanup;
    }

    mbedtls_sha256(CFDataGetBytePtr(pub_data),
                   (size_t)CFDataGetLength(pub_data),
                   out_key32,
                   0);
    if (!memcmp(out_key32, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                           "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 32)) {
        out_key32[31] = 1;
    }
    rc = 0;

cleanup:
    if (err) {
        CFRelease(err);
    }
    CF_SAFE_RELEASE(pub_data);
    CF_SAFE_RELEASE(public_key);
    CF_SAFE_RELEASE(attrs);
    CF_SAFE_RELEASE(key_size_num);
    CF_SAFE_RELEASE(priv_attrs);
    CF_SAFE_RELEASE(find_query);
    CF_SAFE_RELEASE(tag);
    CF_SAFE_RELEASE(private_key);
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
#endif
    *otp_key_1_out = _otp1;
    *otp_key_2_out = _otp2;
}
