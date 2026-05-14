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

#if defined(_MSC_VER)
#include <windows.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"
#include "mbedtls/sha256.h"

#ifndef BCRYPT_KDF_RAW_SECRET
#define BCRYPT_KDF_RAW_SECRET L"RAW_SECRET"
#endif

#define TPM_KEY_NAME   L"pico_novus_tpm_ecdh"
#define SW_PEER_NAME   L"pico_novus_sw_peer_ecdh"
#define SW_LOCAL_NAME  L"pico_novus_sw_local_ecdh"

#ifndef OTP_WINDOWS_TPM_STRICT
#define OTP_WINDOWS_TPM_STRICT 1
#endif

static int win_err(const char *ctx, SECURITY_STATUS st) {
    fprintf(stderr, "[win-tpm] %s failed: 0x%08lx\n", ctx, (unsigned long)st);
    return -1;
}

static const char *ncrypt_status_hint(SECURITY_STATUS st) {
    switch (st) {
        case NTE_DEVICE_NOT_READY:
            return "TPM is not ready (disabled, uninitialized, or inaccessible)";
        case NTE_NOT_SUPPORTED:
            return "operation/algorithm not supported by this provider";
        case NTE_BAD_KEYSET:
            return "keyset not found";
        case NTE_PERM:
            return "permission denied";
        default:
            return "unmapped status";
    }
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

static int open_or_create_persisted_ecdh_p256_key(NCRYPT_PROV_HANDLE prov, LPCWSTR key_name, NCRYPT_KEY_HANDLE *out_key) {
    SECURITY_STATUS st;
    NCRYPT_KEY_HANDLE key = 0;

    if (!out_key) {
        return -1;
    }
    *out_key = 0;

    st = NCryptOpenKey(prov, &key, key_name, 0, 0);
    if (st == NTE_BAD_KEYSET) {
        st = NCryptCreatePersistedKey(prov, &key, NCRYPT_ECDH_P256_ALGORITHM, key_name, 0, 0);
        if (st != ERROR_SUCCESS) {
            return win_err("NCryptCreatePersistedKey", st);
        }
        st = NCryptFinalizeKey(key, 0);
        if (st != ERROR_SUCCESS) {
            NCryptFreeObject(key);
            return win_err("NCryptFinalizeKey", st);
        }
        printf("[win-tpm] Created key '%ls'\n", key_name);
    }
    else if (st != ERROR_SUCCESS) {
        return win_err("NCryptOpenKey", st);
    }
    else {
        printf("[win-tpm] Using existing key '%ls'\n", key_name);
    }

    *out_key = key;
    return 0;
}

static int windows_tpm_vault_load_or_create_key(uint8_t out_key32[32]) {
    int rc = -1;
    SECURITY_STATUS st;
    NCRYPT_PROV_HANDLE tpm_prov = 0;
    NCRYPT_PROV_HANDLE sw_prov = 0;
    NCRYPT_KEY_HANDLE tpm_key = 0;
    NCRYPT_KEY_HANDLE sw_peer_key = 0;
    NCRYPT_KEY_HANDLE imported_peer_pub = 0;
    NCRYPT_SECRET_HANDLE secret = 0;
    PBYTE raw_secret = NULL;
    DWORD raw_secret_len = 0;
    PBYTE peer_pub_blob = NULL;
    DWORD peer_pub_blob_len = 0;

    st = NCryptOpenStorageProvider(&tpm_prov, MS_PLATFORM_CRYPTO_PROVIDER, 0);
    if (st != ERROR_SUCCESS) {
        fprintf(stderr, "[win-tpm] MS_PLATFORM_CRYPTO_PROVIDER unavailable: 0x%08lx (%s)\n", (unsigned long)st, ncrypt_status_hint(st));
#if OTP_WINDOWS_TPM_STRICT
        return -1;
#else
        st = NCryptOpenStorageProvider(&sw_prov, MS_KEY_STORAGE_PROVIDER, 0);
        if (st != ERROR_SUCCESS) {
            return win_err("NCryptOpenStorageProvider(MS_KEY_STORAGE_PROVIDER)", st);
        }
        printf("[win-tpm] Falling back to software KSP (MS_KEY_STORAGE_PROVIDER)\n");
        if (open_or_create_persisted_ecdh_p256_key(sw_prov, SW_LOCAL_NAME, &tpm_key) != 0) {
            goto cleanup;
        }
        if (open_or_create_persisted_ecdh_p256_key(sw_prov, SW_PEER_NAME, &sw_peer_key) != 0) {
            goto cleanup;
        }
        st = NCryptSecretAgreement(tpm_key, sw_peer_key, &secret, 0);
        if (st != ERROR_SUCCESS) {
            win_err("NCryptSecretAgreement(fallback)", st);
            goto cleanup;
        }
        st = NCryptDeriveKey(secret, BCRYPT_KDF_RAW_SECRET, NULL, NULL, 0, &raw_secret_len, 0);
        if (st != ERROR_SUCCESS || raw_secret_len == 0) {
            win_err("NCryptDeriveKey(size/fallback)", st);
            goto cleanup;
        }
        raw_secret = (PBYTE)malloc(raw_secret_len);
        if (!raw_secret) {
            fprintf(stderr, "[win-tpm] malloc(%lu) failed\n", (unsigned long)raw_secret_len);
            goto cleanup;
        }
        st = NCryptDeriveKey(secret, BCRYPT_KDF_RAW_SECRET, NULL, raw_secret, raw_secret_len, &raw_secret_len, 0);
        if (st != ERROR_SUCCESS) {
            win_err("NCryptDeriveKey(data/fallback)", st);
            goto cleanup;
        }
        if (derive_secp256k1_privkey_from_secret(raw_secret, (size_t)raw_secret_len, out_key32) != 0) {
            fprintf(stderr, "[win-tpm] failed deriving secp256k1 private key in software fallback\n");
            goto cleanup;
        }
        rc = 0;
        goto cleanup;
#endif
    }
    else {
        printf("[win-tpm] Using TPM platform provider\n");
    }

    st = NCryptOpenStorageProvider(&sw_prov, MS_KEY_STORAGE_PROVIDER, 0);
    if (st != ERROR_SUCCESS) {
        win_err("NCryptOpenStorageProvider(MS_KEY_STORAGE_PROVIDER)", st);
        goto cleanup;
    }

    if (open_or_create_persisted_ecdh_p256_key(tpm_prov, TPM_KEY_NAME, &tpm_key) != 0) {
        goto cleanup;
    }
    if (open_or_create_persisted_ecdh_p256_key(sw_prov, SW_PEER_NAME, &sw_peer_key) != 0) {
        goto cleanup;
    }

    st = NCryptExportKey(sw_peer_key, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, NULL, 0, &peer_pub_blob_len, 0);
    if (st != ERROR_SUCCESS || peer_pub_blob_len == 0) {
        win_err("NCryptExportKey(size)", st);
        goto cleanup;
    }
    peer_pub_blob = (PBYTE)malloc(peer_pub_blob_len);
    if (!peer_pub_blob) {
        fprintf(stderr, "[win-tpm] malloc(%lu) failed\n", (unsigned long)peer_pub_blob_len);
        goto cleanup;
    }
    st = NCryptExportKey(sw_peer_key, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, peer_pub_blob, peer_pub_blob_len, &peer_pub_blob_len, 0);
    if (st != ERROR_SUCCESS) {
        win_err("NCryptExportKey(data)", st);
        goto cleanup;
    }

    st = NCryptImportKey(tpm_prov, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, &imported_peer_pub, peer_pub_blob, peer_pub_blob_len, 0);
    if (st != ERROR_SUCCESS) {
        win_err("NCryptImportKey(BCRYPT_ECCPUBLIC_BLOB)", st);
        goto cleanup;
    }

    st = NCryptSecretAgreement(tpm_key, imported_peer_pub, &secret, 0);
    if (st != ERROR_SUCCESS) {
        win_err("NCryptSecretAgreement", st);
        goto cleanup;
    }

    st = NCryptDeriveKey(secret, BCRYPT_KDF_RAW_SECRET, NULL, NULL, 0, &raw_secret_len, 0);
    if (st != ERROR_SUCCESS || raw_secret_len == 0) {
        win_err("NCryptDeriveKey(size)", st);
        goto cleanup;
    }

    raw_secret = (PBYTE)malloc(raw_secret_len);
    if (!raw_secret) {
        fprintf(stderr, "[win-tpm] malloc(%lu) failed\n", (unsigned long)raw_secret_len);
        goto cleanup;
    }

    st = NCryptDeriveKey(secret, BCRYPT_KDF_RAW_SECRET, NULL, raw_secret, raw_secret_len, &raw_secret_len, 0);
    if (st != ERROR_SUCCESS) {
        win_err("NCryptDeriveKey(data)", st);
        goto cleanup;
    }

    if (derive_secp256k1_privkey_from_secret(raw_secret, (size_t)raw_secret_len, out_key32) != 0) {
        fprintf(stderr, "[win-tpm] failed deriving secp256k1 private key from ECDH secret\n");
        goto cleanup;
    }

    rc = 0;

cleanup:
    if (peer_pub_blob) {
        SecureZeroMemory(peer_pub_blob, peer_pub_blob_len);
        free(peer_pub_blob);
    }
    if (raw_secret) {
        SecureZeroMemory(raw_secret, raw_secret_len);
        free(raw_secret);
    }
    if (secret) {
        NCryptFreeObject(secret);
    }
    if (imported_peer_pub) {
        NCryptFreeObject(imported_peer_pub);
    }
    if (sw_peer_key) {
        NCryptFreeObject(sw_peer_key);
    }
    if (tpm_key) {
        NCryptFreeObject(tpm_key);
    }
    if (sw_prov) {
        NCryptFreeObject(sw_prov);
    }
    if (tpm_prov) {
        NCryptFreeObject(tpm_prov);
    }
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

#if defined(_MSC_VER)
    if (windows_tpm_vault_load_or_create_key(_otp2) != 0) {
        printf("Warning: failed to load Windows TPM key; using dummy otp_key_2\n");
    }
#endif
    *otp_key_1_out = _otp1;
    *otp_key_2_out = _otp2;
}
