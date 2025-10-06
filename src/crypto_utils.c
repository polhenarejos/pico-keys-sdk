/*
 * This file is part of the Pico Keys SDK distribution (https://github.com/polhenarejos/pico-keys-sdk).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#if defined(ESP_PLATFORM)
#include "esp_compat.h"
#elif defined(PICO_PLATFORM)
#include <pico/unique_id.h>
#endif
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"
#include "crypto_utils.h"
#include "pico_keys.h"
#include "otp.h"

void double_hash_pin(const uint8_t *pin, uint16_t len, uint8_t output[32]) {
    uint8_t o1[32];
    hash_multi(pin, len, o1);
    for (int i = 0; i < sizeof(o1); i++) {
        o1[i] ^= pin[i % len];
    }
    hash_multi(o1, sizeof(o1), output);
}

void double_hash_pin_otp(const uint8_t *pin, uint16_t len, uint8_t output[32]) {
    if (otp_key_1) {
        mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), otp_key_1, 32, pin, len, output);
    } else {
        double_hash_pin(pin, len, output);
    }
}

void hash_multi(const uint8_t *input, uint16_t len, uint8_t output[32]) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    uint16_t iters = 256;
    mbedtls_sha256_starts(&ctx, 0);
    
#ifndef ENABLE_EMULATION
        mbedtls_sha256_update(&ctx, pico_serial.id, sizeof(pico_serial.id));
#endif

    while (iters > len) {
        mbedtls_sha256_update(&ctx, input, len);
        iters -= len;
    }
    if (iters > 0) { // remaining iterations
        mbedtls_sha256_update(&ctx, input, iters);
    }
    mbedtls_sha256_finish(&ctx, output);
    mbedtls_sha256_free(&ctx);
}

void hash256(const uint8_t *input, size_t len, uint8_t output[32]) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);

    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, input, len);

    mbedtls_sha256_finish(&ctx, output);
    mbedtls_sha256_free(&ctx);
}

void generic_hash(mbedtls_md_type_t md, const uint8_t *input, size_t len, uint8_t *output) {
    mbedtls_md(mbedtls_md_info_from_type(md), input, len, output);
}

int aes_encrypt(const uint8_t *key, const uint8_t *iv, uint16_t key_size, int mode, uint8_t *data, uint16_t len) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    uint8_t tmp_iv[IV_SIZE];
    size_t iv_offset = 0;
    memset(tmp_iv, 0, IV_SIZE);
    if (iv) {
        memcpy(tmp_iv, iv, IV_SIZE);
    }
    int r = mbedtls_aes_setkey_enc(&aes, key, key_size);
    if (r != 0) {
        return PICOKEY_EXEC_ERROR;
    }
    if (mode == PICO_KEYS_AES_MODE_CBC) {
        return mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, len, tmp_iv, data, data);
    }
    return mbedtls_aes_crypt_cfb128(&aes, MBEDTLS_AES_ENCRYPT, len, &iv_offset, tmp_iv, data, data);
}

int aes_decrypt(const uint8_t *key, const uint8_t *iv, uint16_t key_size, int mode, uint8_t *data, uint16_t len) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    uint8_t tmp_iv[IV_SIZE];
    size_t iv_offset = 0;
    memset(tmp_iv, 0, IV_SIZE);
    if (iv) {
        memcpy(tmp_iv, iv, IV_SIZE);
    }
    int r = mbedtls_aes_setkey_dec(&aes, key, key_size);
    if (r != 0) {
        return PICOKEY_EXEC_ERROR;
    }
    if (mode == PICO_KEYS_AES_MODE_CBC) {
        return mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, len, tmp_iv, data, data);
    }
    r = mbedtls_aes_setkey_enc(&aes, key, key_size); //CFB requires set_enc instead set_dec
    return mbedtls_aes_crypt_cfb128(&aes, MBEDTLS_AES_DECRYPT, len, &iv_offset, tmp_iv, data, data);
}

int aes_encrypt_cfb_256(const uint8_t *key, const uint8_t *iv, uint8_t *data, uint16_t len) {
    return aes_encrypt(key, iv, 256, PICO_KEYS_AES_MODE_CFB, data, len);
}
int aes_decrypt_cfb_256(const uint8_t *key, const uint8_t *iv, uint8_t *data, uint16_t len) {
    return aes_decrypt(key, iv, 256, PICO_KEYS_AES_MODE_CFB, data, len);
}

struct lv_data {
    unsigned char *value;
    uint8_t len;
};

struct ec_curve_mbed_id {
    struct lv_data curve;
    mbedtls_ecp_group_id id;
};
struct ec_curve_mbed_id ec_curves_mbed[] = {
    {   { (unsigned char *)
          "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
          24 }, MBEDTLS_ECP_DP_SECP192R1 },
    {   { (unsigned char *)
          "\xFF\xFF\xFF\xFF\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
          32 }, MBEDTLS_ECP_DP_SECP256R1 },
    {   { (unsigned char *)
          "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
          48 }, MBEDTLS_ECP_DP_SECP384R1 },
    {   { (unsigned char *)
          "\x01\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
          66 }, MBEDTLS_ECP_DP_SECP521R1 },
    {   { (unsigned char *)
          "\xA9\xFB\x57\xDB\xA1\xEE\xA9\xBC\x3E\x66\x0A\x90\x9D\x83\x8D\x72\x6E\x3B\xF6\x23\xD5\x26\x20\x28\x20\x13\x48\x1D\x1F\x6E\x53\x77",
          32 }, MBEDTLS_ECP_DP_BP256R1 },
    {   { (unsigned char *)
          "\x8C\xB9\x1E\x82\xA3\x38\x6D\x28\x0F\x5D\x6F\x7E\x50\xE6\x41\xDF\x15\x2F\x71\x09\xED\x54\x56\xB4\x12\xB1\xDA\x19\x7F\xB7\x11\x23\xAC\xD3\xA7\x29\x90\x1D\x1A\x71\x87\x47\x00\x13\x31\x07\xEC\x53",
          48 }, MBEDTLS_ECP_DP_BP384R1 },
    {   { (unsigned char *)
          "\xAA\xDD\x9D\xB8\xDB\xE9\xC4\x8B\x3F\xD4\xE6\xAE\x33\xC9\xFC\x07\xCB\x30\x8D\xB3\xB3\xC9\xD2\x0E\xD6\x63\x9C\xCA\x70\x33\x08\x71\x7D\x4D\x9B\x00\x9B\xC6\x68\x42\xAE\xCD\xA1\x2A\xE6\xA3\x80\xE6\x28\x81\xFF\x2F\x2D\x82\xC6\x85\x28\xAA\x60\x56\x58\x3A\x48\xF3",
          64 }, MBEDTLS_ECP_DP_BP512R1 },
    {   { (unsigned char *)
          "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xEE\x37",
          24 }, MBEDTLS_ECP_DP_SECP192K1 },
    {   { (unsigned char *)
          "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFC\x2F",
          32 }, MBEDTLS_ECP_DP_SECP256K1 },
    {   { (unsigned char *)
          "\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xed",
          32 }, MBEDTLS_ECP_DP_CURVE25519 },
    {   { (unsigned char *)
          "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
          56 }, MBEDTLS_ECP_DP_CURVE448 },

    {   { NULL, 0 }, MBEDTLS_ECP_DP_NONE }
};

mbedtls_ecp_group_id ec_get_curve_from_prime(const uint8_t *prime, size_t prime_len) {
    for (struct ec_curve_mbed_id *ec = ec_curves_mbed; ec->id != MBEDTLS_ECP_DP_NONE; ec++) {
        if (prime_len == ec->curve.len && memcmp(prime, ec->curve.value, prime_len) == 0) {
            return ec->id;
        }
    }
    return MBEDTLS_ECP_DP_NONE;
}
