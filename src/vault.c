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

#include "vault.h"

#include <stdlib.h>
#include <string.h>

#include "button.h"
#include "flash.h"
#include "led/led.h"
#include "picokeys.h"
#include "random.h"
#include "serial.h"
#include "vault_container.h"
#if defined(ESP_PLATFORM)
#include "compat/esp_compat.h"
#else
#include "compat/board.h"
#endif
#include "mbedtls/chachapoly.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"

static const uint8_t vault_id_domain[] = "PicoKeys Vault ID v1";
static const uint8_t vault_enroll_info[] = "PicoKeys Vault enrollment v1";
static const uint8_t vault_enrollment_hpke_info[] = "PicoKeys Vault enrollment v2";
static const uint8_t picokeys_vault_ca_der[] = {
    0x30, 0x82, 0x01, 0xEB, 0x30, 0x82, 0x01, 0x6B, 0xA0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x14, 0x2B, 0x37, 0x6A, 0xC8, 0x98, 0x74, 0xE5, 0x0E, 0x80,
    0x1F, 0xB9, 0x61, 0xCD, 0x25, 0x80, 0x48, 0x17, 0xD6, 0x33, 0xA1, 0x30,
    0x05, 0x06, 0x03, 0x2B, 0x65, 0x71, 0x30, 0x3C, 0x31, 0x0B, 0x30, 0x09,
    0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x45, 0x53, 0x31, 0x11, 0x30,
    0x0F, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x08, 0x50, 0x69, 0x63, 0x6F,
    0x4B, 0x65, 0x79, 0x73, 0x31, 0x1A, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0C, 0x11, 0x50, 0x69, 0x63, 0x6F, 0x4B, 0x65, 0x79, 0x73, 0x20,
    0x56, 0x61, 0x75, 0x6C, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1E, 0x17, 0x0D,
    0x32, 0x36, 0x30, 0x38, 0x30, 0x35, 0x31, 0x36, 0x34, 0x34, 0x35, 0x36,
    0x5A, 0x17, 0x0D, 0x33, 0x36, 0x30, 0x38, 0x30, 0x32, 0x31, 0x36, 0x34,
    0x34, 0x35, 0x36, 0x5A, 0x30, 0x3C, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03,
    0x55, 0x04, 0x06, 0x13, 0x02, 0x45, 0x53, 0x31, 0x11, 0x30, 0x0F, 0x06,
    0x03, 0x55, 0x04, 0x0A, 0x0C, 0x08, 0x50, 0x69, 0x63, 0x6F, 0x4B, 0x65,
    0x79, 0x73, 0x31, 0x1A, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C,
    0x11, 0x50, 0x69, 0x63, 0x6F, 0x4B, 0x65, 0x79, 0x73, 0x20, 0x56, 0x61,
    0x75, 0x6C, 0x74, 0x20, 0x43, 0x41, 0x30, 0x43, 0x30, 0x05, 0x06, 0x03,
    0x2B, 0x65, 0x71, 0x03, 0x3A, 0x00, 0xE4, 0x0E, 0x8C, 0x62, 0xC6, 0xD3,
    0x6B, 0x06, 0xC4, 0x0A, 0x54, 0x40, 0x7C, 0x82, 0x1F, 0xDD, 0xAE, 0x93,
    0xF2, 0x88, 0x00, 0x9F, 0xDB, 0x10, 0x67, 0x9A, 0x32, 0x47, 0x62, 0xCE,
    0x92, 0x2A, 0xE2, 0x94, 0x2F, 0x40, 0xF4, 0xEC, 0x0A, 0xFE, 0x72, 0xA4,
    0x18, 0x5D, 0x20, 0x4D, 0x55, 0x97, 0x46, 0xE5, 0x94, 0x7D, 0x11, 0xF0,
    0x5C, 0xE6, 0x00, 0xA3, 0x66, 0x30, 0x64, 0x30, 0x1F, 0x06, 0x03, 0x55,
    0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xAE, 0xFB, 0xD5, 0x12,
    0x05, 0xBA, 0x61, 0xD7, 0x67, 0xE6, 0xAC, 0x78, 0x2E, 0x68, 0xD4, 0x22,
    0xFA, 0xC7, 0xDC, 0x26, 0x30, 0x12, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01,
    0x01, 0xFF, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x00,
    0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0xFF, 0x04, 0x04,
    0x03, 0x02, 0x01, 0x06, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04,
    0x16, 0x04, 0x14, 0xAE, 0xFB, 0xD5, 0x12, 0x05, 0xBA, 0x61, 0xD7, 0x67,
    0xE6, 0xAC, 0x78, 0x2E, 0x68, 0xD4, 0x22, 0xFA, 0xC7, 0xDC, 0x26, 0x30,
    0x05, 0x06, 0x03, 0x2B, 0x65, 0x71, 0x03, 0x73, 0x00, 0x0B, 0xB4, 0x4F,
    0x45, 0x1C, 0x36, 0x77, 0xC1, 0x58, 0xDE, 0x39, 0xC0, 0x29, 0xA0, 0x7C,
    0x9F, 0x8F, 0x75, 0xC2, 0x9E, 0xAE, 0x12, 0x41, 0x00, 0xC8, 0xC9, 0x45,
    0xD1, 0xC0, 0xA6, 0x9A, 0x1D, 0xFA, 0x75, 0xE9, 0xB8, 0x82, 0x00, 0xE3,
    0x81, 0xCF, 0x74, 0x35, 0x59, 0x7F, 0x70, 0x06, 0x3A, 0xEC, 0xDF, 0x52,
    0x42, 0x53, 0x0D, 0xC3, 0x3B, 0x80, 0xF1, 0x1E, 0x3F, 0xC4, 0xAD, 0xC8,
    0xCA, 0x07, 0x4E, 0xBD, 0x5E, 0x35, 0xB7, 0x54, 0x63, 0x08, 0x43, 0x4B,
    0xB1, 0xCC, 0x7F, 0x1A, 0x45, 0x4C, 0xE1, 0x34, 0x57, 0x89, 0x57, 0xAA,
    0x08, 0xD5, 0xF6, 0x54, 0xC5, 0xE7, 0x49, 0xC7, 0xBA, 0xD7, 0x79, 0xAE,
    0xD6, 0x11, 0x05, 0x7A, 0xEF, 0x38, 0x97, 0x05, 0x96, 0x13, 0xC6, 0x95,
    0x01, 0x3A, 0x00,
};
static uint8_t vault_enroll_private[PICOKEYS_VAULT_X448_BYTES];
static uint8_t vault_enroll_public[PICOKEYS_VAULT_X448_BYTES];
static uint8_t vault_enroll_challenge[PICOKEYS_VAULT_ENROLL_CHALLENGE_BYTES];
static bool vault_enroll_active;
static bool vault_enroll_button_accepted;

int picokeys_vault_hash_kvault(const uint8_t kvault[PICOKEYS_VAULT_KEY_SIZE], uint8_t vault_id[PICOKEYS_VAULT_KEY_SIZE]) {
    if (!kvault || !vault_id) {
        log_errstr("vault ID hash: invalid arguments kvault=%p vault_id=%p", (void *)kvault, (void *)vault_id);
        return PICOKEYS_ERR_NULL_PARAM;
    }

    uint8_t input[sizeof(vault_id_domain) - 1 + PICOKEYS_VAULT_KEY_SIZE] = { 0 };
    memcpy(input, vault_id_domain, sizeof(vault_id_domain) - 1);
    memcpy(input + sizeof(vault_id_domain) - 1, kvault, PICOKEYS_VAULT_KEY_SIZE);
    hash256(CONST_BYTE_ARRAY(input, sizeof(input)), vault_id);
    mbedtls_platform_zeroize(input, sizeof(input));
    return PICOKEYS_OK;
}

int picokeys_vault_layer_key(const uint8_t key[PICOKEYS_VAULT_KEY_SIZE], const uint8_t vault_id[PICOKEYS_VAULT_KEY_SIZE], const uint8_t credential_hash[PICOKEYS_VAULT_KEY_SIZE], uint8_t algorithm, uint8_t layer, uint8_t out[PICOKEYS_VAULT_KEY_SIZE]) {
    if (!key || !vault_id || !credential_hash || !out) {
        log_errstr("vault key derivation: invalid arguments key=%p vault_id=%p credential_hash=%p out=%p algorithm=%u layer=%u", (void *)key, (void *)vault_id, (void *)credential_hash, (void *)out, algorithm, layer);
        return PICOKEYS_ERR_NULL_PARAM;
    }

    uint8_t info[sizeof(vault_enroll_info) - 1 + PICOKEYS_VAULT_KEY_SIZE + 2];
    memcpy(info, vault_enroll_info, sizeof(vault_enroll_info) - 1);
    memcpy(info + sizeof(vault_enroll_info) - 1, credential_hash, PICOKEYS_VAULT_KEY_SIZE);
    info[sizeof(vault_enroll_info) - 1 + PICOKEYS_VAULT_KEY_SIZE] = algorithm;
    info[sizeof(vault_enroll_info) - 1 + PICOKEYS_VAULT_KEY_SIZE + 1] = layer;
    int ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), vault_id, PICOKEYS_VAULT_KEY_SIZE, key, PICOKEYS_VAULT_KEY_SIZE, info, sizeof(info), out, PICOKEYS_VAULT_KEY_SIZE);
    mbedtls_platform_zeroize(info, sizeof(info));
    if (ret != 0) {
        log_errstr("vault key derivation: HKDF failed ret=%d algorithm=%u layer=%u", ret, algorithm, layer);
    }
    return ret == 0 ? PICOKEYS_OK : PICOKEYS_EXEC_ERROR;
}

int picokeys_vault_encrypt_layer(uint8_t algorithm, const uint8_t key[PICOKEYS_VAULT_KEY_SIZE], const uint8_t nonce[PICOKEYS_VAULT_BLOB_NONCE_SIZE], const uint8_t *aad, size_t aad_len, const uint8_t *input, size_t input_len, uint8_t *output, uint8_t tag[PICOKEYS_VAULT_BLOB_TAG_SIZE]) {
    if (!key || !nonce || (aad_len > 0 && !aad) || (input_len > 0 && (!input || !output)) || !tag) {
        log_errstr("vault encryption: invalid arguments algorithm=%u key=%p nonce=%p aad=%p aad_len=%zu input=%p input_len=%zu output=%p tag=%p", algorithm, (void *)key, (void *)nonce, (void *)aad, aad_len, (void *)input, input_len, (void *)output, (void *)tag);
        return PICOKEYS_ERR_NULL_PARAM;
    }

    int ret = -1;
    if (algorithm == PICOKEYS_VAULT_ALGORITHM_CHACHAPOLY) {
        mbedtls_chachapoly_context chatx;
        mbedtls_chachapoly_init(&chatx);
        ret = mbedtls_chachapoly_setkey(&chatx, key);
        if (ret != 0) {
            log_errstr("vault encryption: ChaCha20-Poly1305 setup failed ret=%d", ret);
        }
        if (ret == 0) {
            ret = mbedtls_chachapoly_encrypt_and_tag(&chatx, input_len, nonce, aad, aad_len, input, output, tag);
            if (ret != 0) {
                log_errstr("vault encryption: ChaCha20-Poly1305 failed ret=%d input_len=%zu", ret, input_len);
            }
        }
        mbedtls_chachapoly_free(&chatx);
    }
    else if (algorithm == PICOKEYS_VAULT_ALGORITHM_AESGCM) {
        mbedtls_gcm_context gcm;
        mbedtls_gcm_init(&gcm);
        ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
        if (ret != 0) {
            log_errstr("vault encryption: AES-GCM setup failed ret=%d", ret);
        }
        if (ret == 0) {
            ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, input_len, nonce, PICOKEYS_VAULT_BLOB_NONCE_SIZE, aad, aad_len, input, output, PICOKEYS_VAULT_BLOB_TAG_SIZE, tag);
            if (ret != 0) {
                log_errstr("vault encryption: AES-GCM failed ret=%d input_len=%zu", ret, input_len);
            }
        }
        mbedtls_gcm_free(&gcm);
    }
    if (algorithm != PICOKEYS_VAULT_ALGORITHM_CHACHAPOLY && algorithm != PICOKEYS_VAULT_ALGORITHM_AESGCM) {
        log_errstr("vault encryption: unsupported algorithm=%u", algorithm);
    }
    return ret == 0 ? PICOKEYS_OK : PICOKEYS_EXEC_ERROR;
}

int picokeys_vault_decrypt_layer(uint8_t algorithm, const uint8_t key[PICOKEYS_VAULT_KEY_SIZE], const uint8_t nonce[PICOKEYS_VAULT_BLOB_NONCE_SIZE], const uint8_t *aad, size_t aad_len, const uint8_t *input, size_t input_len, const uint8_t tag[PICOKEYS_VAULT_BLOB_TAG_SIZE], uint8_t *output) {
    if (!key || !nonce || (aad_len > 0 && !aad) || (input_len > 0 && (!input || !output)) || !tag) {
        log_errstr("vault decryption: invalid arguments algorithm=%u key=%p nonce=%p aad=%p aad_len=%zu input=%p input_len=%zu tag=%p output=%p", algorithm, (void *)key, (void *)nonce, (void *)aad, aad_len, (void *)input, input_len, (void *)tag, (void *)output);
        return PICOKEYS_ERR_NULL_PARAM;
    }

    int ret = -1;
    if (algorithm == PICOKEYS_VAULT_ALGORITHM_CHACHAPOLY) {
        mbedtls_chachapoly_context chatx;
        mbedtls_chachapoly_init(&chatx);
        ret = mbedtls_chachapoly_setkey(&chatx, key);
        if (ret != 0) {
            log_errstr("vault decryption: ChaCha20-Poly1305 setup failed ret=%d", ret);
        }
        if (ret == 0) {
            ret = mbedtls_chachapoly_auth_decrypt(&chatx, input_len, nonce, aad, aad_len, tag, input, output);
            if (ret != 0) {
                log_errstr("vault decryption: ChaCha20-Poly1305 authentication failed ret=%d input_len=%zu", ret, input_len);
            }
        }
        mbedtls_chachapoly_free(&chatx);
    }
    else if (algorithm == PICOKEYS_VAULT_ALGORITHM_AESGCM) {
        mbedtls_gcm_context gcm;
        mbedtls_gcm_init(&gcm);
        ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
        if (ret != 0) {
            log_errstr("vault decryption: AES-GCM setup failed ret=%d", ret);
        }
        if (ret == 0) {
            ret = mbedtls_gcm_auth_decrypt(&gcm, input_len, nonce, PICOKEYS_VAULT_BLOB_NONCE_SIZE, aad, aad_len, tag, PICOKEYS_VAULT_BLOB_TAG_SIZE, input, output);
            if (ret != 0) {
                log_errstr("vault decryption: AES-GCM authentication failed ret=%d input_len=%zu", ret, input_len);
            }
        }
        mbedtls_gcm_free(&gcm);
    }
    if (algorithm != PICOKEYS_VAULT_ALGORITHM_CHACHAPOLY && algorithm != PICOKEYS_VAULT_ALGORITHM_AESGCM) {
        log_errstr("vault decryption: unsupported algorithm=%u", algorithm);
    }
    return ret == 0 ? PICOKEYS_OK : PICOKEYS_VERIFICATION_FAILED;
}

static int vault_x448_generate(uint8_t private_key[PICOKEYS_VAULT_X448_BYTES], uint8_t public_key[PICOKEYS_VAULT_X448_BYTES]) {
    if (!private_key || !public_key) {
        log_errstr("vault enrollment: X448 generate invalid arguments private_key=%p public_key=%p", (void *)private_key, (void *)public_key);
        return PICOKEYS_ERR_NULL_PARAM;
    }

    mbedtls_ecp_keypair key;
    size_t private_len = 0;
    size_t public_len = 0;
    mbedtls_ecp_keypair_init(&key);
    int ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_CURVE448, &key, random_fill_iterator, NULL);
    if (ret == 0) {
        ret = mbedtls_ecp_write_key_ext(&key, &private_len, private_key, PICOKEYS_VAULT_X448_BYTES);
    }
    if (ret == 0) {
        ret = mbedtls_ecp_point_write_binary(&key.MBEDTLS_PRIVATE(grp), &key.MBEDTLS_PRIVATE(Q), MBEDTLS_ECP_PF_UNCOMPRESSED, &public_len, public_key, PICOKEYS_VAULT_X448_BYTES);
    }
    mbedtls_ecp_keypair_free(&key);
    if (ret != 0) {
        log_errstr("vault enrollment: X448 key generation failed: %d", ret);
        return PICOKEYS_EXEC_ERROR;
    }
    if (private_len != PICOKEYS_VAULT_X448_BYTES || public_len != PICOKEYS_VAULT_X448_BYTES) {
        log_errstr("vault enrollment: X448 key length invalid private_len=%zu public_len=%zu expected=%u", private_len, public_len, PICOKEYS_VAULT_X448_BYTES);
        return PICOKEYS_WRONG_LENGTH;
    }
    return PICOKEYS_OK;
}

static int vault_x448_shared(const uint8_t private_key[PICOKEYS_VAULT_X448_BYTES], const uint8_t peer_public[PICOKEYS_VAULT_X448_BYTES], uint8_t shared[PICOKEYS_VAULT_X448_BYTES]) {
    if (!private_key || !peer_public || !shared) {
        log_errstr("vault enrollment: X448 shared invalid arguments private_key=%p peer_public=%p shared=%p", (void *)private_key, (void *)peer_public, (void *)shared);
        return PICOKEYS_ERR_NULL_PARAM;
    }

    mbedtls_ecdh_context ecdh;
    mbedtls_ecp_keypair ours;
    mbedtls_ecp_keypair theirs;
    size_t shared_len = 0;
    mbedtls_ecdh_init(&ecdh);
    mbedtls_ecp_keypair_init(&ours);
    mbedtls_ecp_keypair_init(&theirs);
    int ret = mbedtls_ecp_group_load(&ours.MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_CURVE448);
    if (ret == 0) {
        ret = mbedtls_ecp_group_load(&theirs.MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_CURVE448);
    }
    if (ret == 0) {
        ret = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_CURVE448, &ours, private_key, PICOKEYS_VAULT_X448_BYTES);
    }
    if (ret == 0) {
        ret = mbedtls_ecp_point_read_binary(&theirs.MBEDTLS_PRIVATE(grp), &theirs.MBEDTLS_PRIVATE(Q), peer_public, PICOKEYS_VAULT_X448_BYTES);
    }
    if (ret == 0) {
        ret = mbedtls_ecdh_setup(&ecdh, MBEDTLS_ECP_DP_CURVE448);
    }
    if (ret == 0) {
        ret = mbedtls_ecdh_get_params(&ecdh, &ours, MBEDTLS_ECDH_OURS);
    }
    if (ret == 0) {
        ret = mbedtls_ecdh_get_params(&ecdh, &theirs, MBEDTLS_ECDH_THEIRS);
    }
    if (ret == 0) {
        ret = mbedtls_ecdh_calc_secret(&ecdh, &shared_len, shared, PICOKEYS_VAULT_X448_BYTES, random_fill_iterator, NULL);
    }
    mbedtls_ecdh_free(&ecdh);
    mbedtls_ecp_keypair_free(&ours);
    mbedtls_ecp_keypair_free(&theirs);
    if (ret != 0) {
        log_errstr("vault enrollment: X448 shared secret failed: %d", ret);
        return PICOKEYS_EXEC_ERROR;
    }
    if (shared_len != PICOKEYS_VAULT_X448_BYTES) {
        log_errstr("vault enrollment: X448 shared secret length invalid actual=%zu expected=%u", shared_len, PICOKEYS_VAULT_X448_BYTES);
        return PICOKEYS_WRONG_LENGTH;
    }
    uint8_t nonzero = 0;
    for (size_t i = 0; i < PICOKEYS_VAULT_X448_BYTES; i++) {
        nonzero |= shared[i];
    }
    if (nonzero == 0) {
        mbedtls_platform_zeroize(shared, PICOKEYS_VAULT_X448_BYTES);
        log_errstr("vault enrollment: X448 shared secret is all zero");
        return PICOKEYS_VERIFICATION_FAILED;
    }
    return PICOKEYS_OK;
}

#define VAULT_HPKE_NH 64u
#define VAULT_HPKE_NK 32u
#define VAULT_HPKE_NN 12u
#define VAULT_HPKE_NT 16u
#define VAULT_HPKE_KEM_SUITE_ID_LEN 5u
#define VAULT_HPKE_SUITE_ID_LEN 10u
#define VAULT_HPKE_EXPAND_INFO_MAX 256u
#define VAULT_HPKE_LABELED_INPUT_MAX 256u

static int vault_hpke_hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, uint8_t prk[VAULT_HPKE_NH]) {
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    uint8_t zero_salt[VAULT_HPKE_NH] = { 0 };
    if (!md || !prk || (!salt && salt_len > 0) || (!ikm && ikm_len > 0) || salt_len > VAULT_HPKE_NH) {
        return PICOKEYS_WRONG_DATA;
    }
    if (salt_len == 0) {
        salt = zero_salt;
        salt_len = sizeof(zero_salt);
    }
    int ret = mbedtls_md_hmac(md, salt, salt_len, ikm, ikm_len, prk);
    mbedtls_platform_zeroize(zero_salt, sizeof(zero_salt));
    return ret == 0 ? PICOKEYS_OK : PICOKEYS_EXEC_ERROR;
}

static int vault_hpke_hkdf_expand(const uint8_t prk[VAULT_HPKE_NH], const uint8_t *info, size_t info_len, uint8_t *output, size_t output_len) {
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    uint8_t input[VAULT_HPKE_NH + VAULT_HPKE_EXPAND_INFO_MAX + 1u] = { 0 };
    uint8_t previous[VAULT_HPKE_NH] = { 0 };
    if (!md || !prk || (!info && info_len > 0) || (!output && output_len > 0) || info_len > VAULT_HPKE_EXPAND_INFO_MAX || output_len > 255u * VAULT_HPKE_NH) {
        return PICOKEYS_WRONG_DATA;
    }

    size_t written = 0;
    uint8_t counter = 1;
    int ret = 0;
    while (written < output_len) {
        size_t input_len = 0;
        if (counter > 1) {
            memcpy(input, previous, sizeof(previous));
            input_len = sizeof(previous);
        }
        if (info_len > 0) {
            memcpy(input + input_len, info, info_len);
            input_len += info_len;
        }
        input[input_len++] = counter;
        ret = mbedtls_md_hmac(md, prk, VAULT_HPKE_NH, input, input_len, previous);
        if (ret != 0) {
            break;
        }
        size_t copy_len = output_len - written;
        if (copy_len > sizeof(previous)) {
            copy_len = sizeof(previous);
        }
        memcpy(output + written, previous, copy_len);
        written += copy_len;
        counter++;
    }
    mbedtls_platform_zeroize(input, sizeof(input));
    mbedtls_platform_zeroize(previous, sizeof(previous));
    return ret == 0 ? PICOKEYS_OK : PICOKEYS_EXEC_ERROR;
}

static int vault_hpke_labeled_extract(const uint8_t *suite_id, size_t suite_id_len, const uint8_t *salt, size_t salt_len, const uint8_t *label, size_t label_len, const uint8_t *ikm, size_t ikm_len, uint8_t output[VAULT_HPKE_NH]) {
    static const uint8_t version[] = "HPKE-v1";
    uint8_t labeled_ikm[VAULT_HPKE_LABELED_INPUT_MAX] = { 0 };
    size_t labeled_len = sizeof(version) - 1u + suite_id_len + label_len + ikm_len;
    if (!suite_id || suite_id_len == 0 || (!label && label_len > 0) || (!ikm && ikm_len > 0) || labeled_len > sizeof(labeled_ikm)) {
        return PICOKEYS_WRONG_DATA;
    }
    memcpy(labeled_ikm, version, sizeof(version) - 1u);
    memcpy(labeled_ikm + sizeof(version) - 1u, suite_id, suite_id_len);
    memcpy(labeled_ikm + sizeof(version) - 1u + suite_id_len, label, label_len);
    memcpy(labeled_ikm + sizeof(version) - 1u + suite_id_len + label_len, ikm, ikm_len);
    int ret = vault_hpke_hkdf_extract(salt, salt_len, labeled_ikm, labeled_len, output);
    mbedtls_platform_zeroize(labeled_ikm, sizeof(labeled_ikm));
    return ret;
}

static int vault_hpke_labeled_expand(const uint8_t *suite_id, size_t suite_id_len, const uint8_t prk[VAULT_HPKE_NH], const uint8_t *label, size_t label_len, const uint8_t *info, size_t info_len, uint8_t *output, size_t output_len) {
    static const uint8_t version[] = "HPKE-v1";
    uint8_t labeled_info[VAULT_HPKE_EXPAND_INFO_MAX] = { 0 };
    size_t labeled_len = 2u + sizeof(version) - 1u + suite_id_len + label_len + info_len;
    if (!suite_id || suite_id_len == 0 || !prk || (!label && label_len > 0) || (!info && info_len > 0) || !output || output_len > 0xffffu || labeled_len > sizeof(labeled_info)) {
        return PICOKEYS_WRONG_DATA;
    }
    labeled_info[0] = (uint8_t)(output_len >> 8);
    labeled_info[1] = (uint8_t)output_len;
    memcpy(labeled_info + 2u, version, sizeof(version) - 1u);
    memcpy(labeled_info + 2u + sizeof(version) - 1u, suite_id, suite_id_len);
    memcpy(labeled_info + 2u + sizeof(version) - 1u + suite_id_len, label, label_len);
    memcpy(labeled_info + 2u + sizeof(version) - 1u + suite_id_len + label_len, info, info_len);
    int ret = vault_hpke_hkdf_expand(prk, labeled_info, labeled_len, output, output_len);
    mbedtls_platform_zeroize(labeled_info, sizeof(labeled_info));
    return ret;
}

static int vault_hpke_auth_decap(const uint8_t enc[PICOKEYS_VAULT_X448_BYTES], const uint8_t recipient_private[PICOKEYS_VAULT_X448_BYTES], const uint8_t recipient_public[PICOKEYS_VAULT_X448_BYTES], const uint8_t sender_public[PICOKEYS_VAULT_X448_BYTES], const uint8_t *info, size_t info_len, const uint8_t *aad, size_t aad_len, const uint8_t *ciphertext, size_t ciphertext_len, uint8_t *plaintext) {
    static const uint8_t kem_suite_id[VAULT_HPKE_KEM_SUITE_ID_LEN] = { 'K', 'E', 'M', 0x00, 0x21 };
    static const uint8_t hpke_suite_id[VAULT_HPKE_SUITE_ID_LEN] = { 'H', 'P', 'K', 'E', 0x00, 0x21, 0x00, 0x03, 0x00, 0x02 };
    static const uint8_t eae_prk_label[] = "eae_prk";
    static const uint8_t shared_secret_label[] = "shared_secret";
    static const uint8_t psk_id_hash_label[] = "psk_id_hash";
    static const uint8_t info_hash_label[] = "info_hash";
    static const uint8_t secret_label[] = "secret";
    static const uint8_t key_label[] = "key";
    static const uint8_t base_nonce_label[] = "base_nonce";
    static const uint8_t empty[] = { 0 };
    uint8_t dh[PICOKEYS_VAULT_X448_BYTES * 2u] = { 0 };
    uint8_t kem_context[PICOKEYS_VAULT_X448_BYTES * 3u] = { 0 };
    uint8_t eae_prk[VAULT_HPKE_NH] = { 0 };
    uint8_t shared_secret[VAULT_HPKE_NH] = { 0 };
    uint8_t psk_id_hash[VAULT_HPKE_NH] = { 0 };
    uint8_t info_hash[VAULT_HPKE_NH] = { 0 };
    uint8_t key_schedule_context[1u + VAULT_HPKE_NH * 2u] = { 0 };
    uint8_t secret[VAULT_HPKE_NH] = { 0 };
    uint8_t key[VAULT_HPKE_NK] = { 0 };
    uint8_t nonce[VAULT_HPKE_NN] = { 0 };
    if (!enc || !recipient_private || !recipient_public || !sender_public || (!info && info_len > 0) || (!aad && aad_len > 0) || !ciphertext || !plaintext || ciphertext_len < VAULT_HPKE_NT) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    int ret = vault_x448_shared(recipient_private, enc, dh);
    if (ret == PICOKEYS_OK) {
        ret = vault_x448_shared(recipient_private, sender_public, dh + PICOKEYS_VAULT_X448_BYTES);
    }
    if (ret == PICOKEYS_OK) {
        memcpy(kem_context, enc, PICOKEYS_VAULT_X448_BYTES);
        memcpy(kem_context + PICOKEYS_VAULT_X448_BYTES, recipient_public, PICOKEYS_VAULT_X448_BYTES);
        memcpy(kem_context + PICOKEYS_VAULT_X448_BYTES * 2u, sender_public, PICOKEYS_VAULT_X448_BYTES);
        ret = vault_hpke_labeled_extract(kem_suite_id, sizeof(kem_suite_id), NULL, 0, eae_prk_label, sizeof(eae_prk_label) - 1u, dh, sizeof(dh), eae_prk);
    }
    if (ret == PICOKEYS_OK) {
        ret = vault_hpke_labeled_expand(kem_suite_id, sizeof(kem_suite_id), eae_prk, shared_secret_label, sizeof(shared_secret_label) - 1u, kem_context, sizeof(kem_context), shared_secret, sizeof(shared_secret));
    }
    if (ret == PICOKEYS_OK) {
        ret = vault_hpke_labeled_extract(hpke_suite_id, sizeof(hpke_suite_id), NULL, 0, psk_id_hash_label, sizeof(psk_id_hash_label) - 1u, empty, 0, psk_id_hash);
    }
    if (ret == PICOKEYS_OK) {
        ret = vault_hpke_labeled_extract(hpke_suite_id, sizeof(hpke_suite_id), NULL, 0, info_hash_label, sizeof(info_hash_label) - 1u, info, info_len, info_hash);
    }
    if (ret == PICOKEYS_OK) {
        key_schedule_context[0] = 0x02;
        memcpy(key_schedule_context + 1u, psk_id_hash, sizeof(psk_id_hash));
        memcpy(key_schedule_context + 1u + sizeof(psk_id_hash), info_hash, sizeof(info_hash));
        ret = vault_hpke_labeled_extract(hpke_suite_id, sizeof(hpke_suite_id), shared_secret, sizeof(shared_secret), secret_label, sizeof(secret_label) - 1u, empty, 0, secret);
    }
    if (ret == PICOKEYS_OK) {
        ret = vault_hpke_labeled_expand(hpke_suite_id, sizeof(hpke_suite_id), secret, key_label, sizeof(key_label) - 1u, key_schedule_context, sizeof(key_schedule_context), key, sizeof(key));
    }
    if (ret == PICOKEYS_OK) {
        ret = vault_hpke_labeled_expand(hpke_suite_id, sizeof(hpke_suite_id), secret, base_nonce_label, sizeof(base_nonce_label) - 1u, key_schedule_context, sizeof(key_schedule_context), nonce, sizeof(nonce));
    }
    if (ret == PICOKEYS_OK) {
        mbedtls_gcm_context gcm;
        mbedtls_gcm_init(&gcm);
        ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
        if (ret == 0) {
            ret = mbedtls_gcm_auth_decrypt(&gcm, ciphertext_len - VAULT_HPKE_NT, nonce, sizeof(nonce), aad, aad_len, ciphertext + ciphertext_len - VAULT_HPKE_NT, VAULT_HPKE_NT, ciphertext, plaintext);
        }
        mbedtls_gcm_free(&gcm);
        if (ret != 0) {
            log_errstr("vault enrollment: HPKE authentication failed ret=%d ciphertext_len=%zu", ret, ciphertext_len);
        }
    }
    mbedtls_platform_zeroize(dh, sizeof(dh));
    mbedtls_platform_zeroize(kem_context, sizeof(kem_context));
    mbedtls_platform_zeroize(eae_prk, sizeof(eae_prk));
    mbedtls_platform_zeroize(shared_secret, sizeof(shared_secret));
    mbedtls_platform_zeroize(psk_id_hash, sizeof(psk_id_hash));
    mbedtls_platform_zeroize(info_hash, sizeof(info_hash));
    mbedtls_platform_zeroize(key_schedule_context, sizeof(key_schedule_context));
    mbedtls_platform_zeroize(secret, sizeof(secret));
    mbedtls_platform_zeroize(key, sizeof(key));
    mbedtls_platform_zeroize(nonce, sizeof(nonce));
    return ret == 0 ? PICOKEYS_OK : PICOKEYS_VERIFICATION_FAILED;
}

static bool picokeys_vault_enrollment_active(void) {
    return vault_enroll_active;
}

#ifndef ENABLE_EMULATION
static bool vault_enrollment_window_open(void) {
    return board_millis() < PICOKEYS_VAULT_ENROLL_WINDOW_MS;
}
#endif

bool picokeys_vault_enrollment_button_ready(void) {
#ifdef ENABLE_EMULATION
    vault_enroll_button_accepted = true;
    return true;
#else
    if (!vault_enrollment_window_open() && !vault_enroll_active) {
        vault_enroll_button_accepted = false;
        button_pressed_duration = 0;
        led_set_mode(MODE_MOUNTED);
        return false;
    }
    if (button_pressed_duration >= PICOKEYS_VAULT_ENROLL_HOLD_MS) {
        if (!vault_enroll_button_accepted) {
            led_set_mode(MODE_BUTTON);
        }
        vault_enroll_button_accepted = true;
    }
    return vault_enroll_button_accepted;
#endif
}

int picokeys_vault_enrollment_start(uint8_t public_key[PICOKEYS_VAULT_X448_BYTES], uint8_t challenge[PICOKEYS_VAULT_ENROLL_CHALLENGE_BYTES]) {
    if (!public_key || !challenge) {
        log_errstr("vault enrollment: ceremony start invalid arguments public_key=%p challenge=%p", (void *)public_key, (void *)challenge);
        return PICOKEYS_ERR_NULL_PARAM;
    }

    picokeys_vault_enrollment_clear();
    int ret = vault_x448_generate(vault_enroll_private, public_key);
    if (ret == PICOKEYS_OK) {
        memcpy(vault_enroll_public, public_key, PICOKEYS_VAULT_X448_BYTES);
        random_fill_buffer(BYTE_ARRAY(vault_enroll_challenge, sizeof(vault_enroll_challenge)));
        memcpy(challenge, vault_enroll_challenge, sizeof(vault_enroll_challenge));
        vault_enroll_active = true;
#ifndef ENABLE_EMULATION
        led_set_mode(MODE_BUTTON);
#endif
    }
    return ret;
}

void picokeys_vault_enrollment_clear(void) {
    mbedtls_platform_zeroize(vault_enroll_private, sizeof(vault_enroll_private));
    mbedtls_platform_zeroize(vault_enroll_challenge, sizeof(vault_enroll_challenge));
    mbedtls_platform_zeroize(vault_enroll_public, sizeof(vault_enroll_public));
    vault_enroll_active = false;
    vault_enroll_button_accepted = false;
}

void picokeys_vault_enrollment_reset(void) {
    picokeys_vault_enrollment_clear();
#ifndef ENABLE_EMULATION
    button_pressed_duration = 0;
    led_set_mode(MODE_MOUNTED);
#endif
}

static int vault_enrollment_validate_certificate(mbedtls_x509_crt *certificate) {
    if (!certificate) {
        log_errstr("vault enrollment: certificate validation invalid certificate=%p", (void *)certificate);
        return PICOKEYS_ERR_NULL_PARAM;
    }

    mbedtls_x509_crt ca;
    uint32_t flags = 0;
    mbedtls_x509_crt_init(&ca);
    int ret = mbedtls_x509_crt_parse(&ca, picokeys_vault_ca_der, sizeof(picokeys_vault_ca_der));
    if (ret == 0) {
        ret = mbedtls_x509_crt_verify(certificate, &ca, NULL, NULL, &flags, NULL, NULL);
    }
    mbedtls_x509_crt_free(&ca);
    if (ret != 0 || flags != 0) {
        log_errstr("vault enrollment: certificate validation failed ret=%d flags=0x%08lx", ret, (unsigned long)flags);
    }
    return ret != 0 ? PICOKEYS_EXEC_ERROR : (flags == 0 ? PICOKEYS_OK : PICOKEYS_VERIFICATION_FAILED);
}

static int vault_enrollment_validate_serial(mbedtls_x509_crt *certificate) {
    if (!certificate || !certificate->subject_alt_names.buf.p) {
        log_errstr("vault enrollment: certificate serial missing certificate=%p has_san=%d", (void *)certificate, certificate ? certificate->subject_alt_names.buf.p != NULL : 0);
        return PICOKEYS_VERIFICATION_FAILED;
    }

#ifdef ENABLE_EMULATION
    return PICOKEYS_OK;
#else
    size_t serial_len = strlen(pico_serial_str);
    for (mbedtls_x509_sequence *entry = &certificate->subject_alt_names; entry; entry = entry->next) {
        mbedtls_x509_subject_alternative_name san = { 0 };
        int ret = mbedtls_x509_parse_subject_alt_name(&entry->buf, &san);
        if (ret == 0 && (san.type == MBEDTLS_X509_SAN_DNS_NAME || san.type == MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER) && san.san.unstructured_name.len == serial_len && memcmp(san.san.unstructured_name.p, pico_serial_str, serial_len) == 0) {
            mbedtls_x509_free_subject_alt_name(&san);
            return PICOKEYS_OK;
        }
        mbedtls_x509_free_subject_alt_name(&san);
    }
    log_errstr("vault enrollment: certificate serial mismatch expected=\"%.*s\" expected_len=%zu", (int)(serial_len > 32u ? 32u : serial_len), pico_serial_str, serial_len);
    return PICOKEYS_VERIFICATION_FAILED;
#endif
}

static int vault_enrollment_certificate_public(mbedtls_x509_crt *certificate, uint8_t public_key[PICOKEYS_VAULT_X448_BYTES]) {
    if (!certificate || !public_key || (mbedtls_pk_get_type(&certificate->pk) != MBEDTLS_PK_ECKEY && mbedtls_pk_get_type(&certificate->pk) != MBEDTLS_PK_ECKEY_DH)) {
        log_errstr("vault enrollment: certificate public key invalid certificate=%p public_key=%p type=%d", (void *)certificate, (void *)public_key, certificate ? mbedtls_pk_get_type(&certificate->pk) : MBEDTLS_PK_NONE);
        return PICOKEYS_WRONG_DATA;
    }

    mbedtls_ecp_keypair *key = mbedtls_pk_ec(certificate->pk);
    if (!key || key->MBEDTLS_PRIVATE(grp).id != MBEDTLS_ECP_DP_CURVE448) {
        log_errstr("vault enrollment: certificate public key curve invalid key=%p curve=%d expected=%d", (void *)key, key ? key->MBEDTLS_PRIVATE(grp).id : MBEDTLS_ECP_DP_NONE, MBEDTLS_ECP_DP_CURVE448);
        return PICOKEYS_WRONG_DATA;
    }

    size_t public_len = 0;
    int ret = mbedtls_ecp_point_write_binary(&key->MBEDTLS_PRIVATE(grp), &key->MBEDTLS_PRIVATE(Q), MBEDTLS_ECP_PF_UNCOMPRESSED, &public_len, public_key, PICOKEYS_VAULT_X448_BYTES);
    if (ret != 0 || public_len != PICOKEYS_VAULT_X448_BYTES) {
        log_errstr("vault enrollment: certificate public key extraction failed ret=%d public_len=%zu expected=%u", ret, public_len, PICOKEYS_VAULT_X448_BYTES);
    }
    return ret == 0 && public_len == PICOKEYS_VAULT_X448_BYTES ? PICOKEYS_OK : PICOKEYS_WRONG_DATA;
}

int picokeys_vault_enrollment_decode(const uint8_t *packet, size_t packet_len, uint8_t kvault[PICOKEYS_VAULT_KEY_SIZE], uint8_t *metadata, size_t metadata_capacity, size_t *metadata_len) {
    if (!picokeys_vault_enrollment_active() || !packet || !kvault || !metadata_len || (metadata_capacity > 0 && !metadata) || packet_len < PICOKEYS_VAULT_ENROLL_MIN_PACKET_LEN) {
        log_errstr("vault enrollment: invalid or inactive packet active=%d packet=%p packet_len=%zu kvault=%p metadata=%p metadata_capacity=%zu metadata_len=%p", picokeys_vault_enrollment_active(), (void *)packet, packet_len, (void *)kvault, (void *)metadata, metadata_capacity, (void *)metadata_len);
        picokeys_vault_enrollment_reset();
        return PICOKEYS_WRONG_LENGTH;
    }

    *metadata_len = 0;
    uint16_t certificate_len = ((uint16_t)packet[0] << 8) | packet[1];
    size_t certificate_offset = 2;
    size_t encapsulated_offset = certificate_offset + certificate_len;
    size_t ciphertext_offset = encapsulated_offset + PICOKEYS_VAULT_X448_BYTES;
    if (certificate_len == 0 || certificate_len > PICOKEYS_VAULT_ENROLL_CERT_MAX || ciphertext_offset > packet_len || packet_len < ciphertext_offset + 16u + PICOKEYS_VAULT_KEY_SIZE) {
        log_errstr("vault enrollment: invalid certificate length=%u packet_len=%zu ciphertext_offset=%zu", certificate_len, packet_len, ciphertext_offset);
        picokeys_vault_enrollment_reset();
        return PICOKEYS_WRONG_LENGTH;
    }

    size_t ciphertext_len = packet_len - ciphertext_offset;
    if (ciphertext_len < PICOKEYS_VAULT_KEY_SIZE + 16u || ciphertext_len > PICOKEYS_VAULT_ENROLL_PLAIN_MAX + 16u) {
        log_errstr("vault enrollment: invalid ciphertext length=%zu min=%u max=%u", ciphertext_len, PICOKEYS_VAULT_KEY_SIZE + 16u, PICOKEYS_VAULT_ENROLL_PLAIN_MAX + 16u);
        picokeys_vault_enrollment_reset();
        return PICOKEYS_WRONG_LENGTH;
    }

    mbedtls_x509_crt certificate;
    mbedtls_x509_crt_init(&certificate);
    int ret = mbedtls_x509_crt_parse(&certificate, packet + certificate_offset, certificate_len);
    if (ret != 0) {
        log_errstr("vault enrollment: certificate parsing failed: %d", ret);
    }
    if (ret == 0) {
        ret = vault_enrollment_validate_certificate(&certificate);
    }
    if (ret == PICOKEYS_OK) {
        ret = vault_enrollment_validate_serial(&certificate);
    }

    uint8_t certificate_public[PICOKEYS_VAULT_X448_BYTES] = { 0 };
    if (ret == PICOKEYS_OK) {
        ret = vault_enrollment_certificate_public(&certificate, certificate_public);
    }
    mbedtls_x509_crt_free(&certificate);
    if (ret != PICOKEYS_OK) {
        mbedtls_platform_zeroize(certificate_public, sizeof(certificate_public));
        picokeys_vault_enrollment_reset();
        return PICOKEYS_VERIFICATION_FAILED;
    }

    uint8_t enrollment_plain[PICOKEYS_VAULT_ENROLL_PLAIN_MAX] = { 0 };
    size_t plain_len = ciphertext_len - 16u;
    uint8_t info[sizeof(vault_enrollment_hpke_info) - 1u + PICOKEYS_VAULT_ENROLL_CHALLENGE_BYTES] = { 0 };
    memcpy(info, vault_enrollment_hpke_info, sizeof(vault_enrollment_hpke_info) - 1u);
    memcpy(info + sizeof(vault_enrollment_hpke_info) - 1u, vault_enroll_challenge, PICOKEYS_VAULT_ENROLL_CHALLENGE_BYTES);
    ret = vault_hpke_auth_decap(packet + encapsulated_offset, vault_enroll_private, vault_enroll_public, certificate_public, info, sizeof(info), packet + certificate_offset, certificate_len, packet + ciphertext_offset, ciphertext_len, enrollment_plain);

    size_t plain_metadata_len = 0;
    if (ret == 0 && plain_len == PICOKEYS_VAULT_KEY_SIZE) {
        memcpy(kvault, enrollment_plain, PICOKEYS_VAULT_KEY_SIZE);
    }
    else if (ret == 0 && plain_len >= PICOKEYS_VAULT_KEY_SIZE + 1u && enrollment_plain[PICOKEYS_VAULT_KEY_SIZE] <= 64u && plain_len == PICOKEYS_VAULT_KEY_SIZE + 1u + enrollment_plain[PICOKEYS_VAULT_KEY_SIZE]) {
        memcpy(kvault, enrollment_plain, PICOKEYS_VAULT_KEY_SIZE);
        plain_metadata_len = enrollment_plain[PICOKEYS_VAULT_KEY_SIZE];
        if (plain_metadata_len > metadata_capacity) {
            ret = PICOKEYS_ERR_NO_MEMORY;
            log_errstr("vault enrollment: metadata buffer too small len=%zu capacity=%zu", plain_metadata_len, metadata_capacity);
        }
        else if (plain_metadata_len > 0 && metadata) {
            memcpy(metadata, enrollment_plain + PICOKEYS_VAULT_KEY_SIZE + 1u, plain_metadata_len);
        }
    }
    else if (ret == 0) {
        ret = PICOKEYS_WRONG_LENGTH;
        log_errstr("vault enrollment: decrypted payload format invalid plain_len=%zu metadata_len=%u", plain_len, plain_len > PICOKEYS_VAULT_KEY_SIZE ? enrollment_plain[PICOKEYS_VAULT_KEY_SIZE] : 0u);
    }

    if (ret == PICOKEYS_OK) {
        *metadata_len = plain_metadata_len;
    }

    mbedtls_platform_zeroize(info, sizeof(info));
    mbedtls_platform_zeroize(certificate_public, sizeof(certificate_public));
    mbedtls_platform_zeroize(enrollment_plain, sizeof(enrollment_plain));
    picokeys_vault_enrollment_reset();
    return ret;
}

bool picokeys_vault_algorithm_valid(uint8_t algorithm) {
    return algorithm >= PICOKEYS_VAULT_ALGORITHM_CHACHAPOLY && algorithm <= PICOKEYS_VAULT_ALGORITHM_AESGCM_CHACHAPOLY;
}

size_t picokeys_vault_algorithm_layers(uint8_t algorithm) {
    return algorithm >= PICOKEYS_VAULT_ALGORITHM_CHACHAPOLY_AESGCM ? 2u : 1u;
}

uint8_t picokeys_vault_algorithm_layer(uint8_t algorithm, size_t index) {
    if (algorithm == PICOKEYS_VAULT_ALGORITHM_CHACHAPOLY_AESGCM) {
        return index == 0 ? PICOKEYS_VAULT_ALGORITHM_CHACHAPOLY : PICOKEYS_VAULT_ALGORITHM_AESGCM;
    }
    if (algorithm == PICOKEYS_VAULT_ALGORITHM_AESGCM_CHACHAPOLY) {
        return index == 0 ? PICOKEYS_VAULT_ALGORITHM_AESGCM : PICOKEYS_VAULT_ALGORITHM_CHACHAPOLY;
    }
    return algorithm;
}
