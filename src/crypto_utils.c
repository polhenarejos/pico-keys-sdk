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
#include "serial.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/gcm.h"
#include "mbedtls/base64.h"
#include "crypto_utils.h"
#include "otp.h"
#include "random.h"

static const mbedtls_md_info_t *SHA256(void) {
    return mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
}

void derive_kbase(uint8_t kbase[32]) {
    const uint8_t nootp_salt[] = "NO-OTP";
    if (otp_key_1) {
        mbedtls_hkdf(SHA256(), pico_serial_hash, sizeof(pico_serial_hash), otp_key_1, 32, (const uint8_t *)"DEVICE/ROOT", 12, kbase, 32);
    }
    else {
        mbedtls_hkdf(SHA256(), nootp_salt, sizeof(nootp_salt)-1, pico_serial_hash, sizeof(pico_serial_hash), (const uint8_t *)"DEVICE/ROOT", 12, kbase, 32);
    }
}

void derive_kver(const uint8_t *pin, size_t pin_len, uint8_t kver[32]) {
    uint8_t kbase[32];
    derive_kbase(kbase);
    mbedtls_md_hmac(SHA256(), kbase, 32, pin, pin_len, kver);
    mbedtls_platform_zeroize(kbase, sizeof(kbase));
}

void pin_derive_verifier(const uint8_t *pin, size_t pin_len, uint8_t verifier[32]) {
    uint8_t kver[32];
    derive_kver(pin, pin_len, kver);
    mbedtls_hkdf(SHA256(), pico_serial_hash, sizeof(pico_serial_hash), kver, 32, (const uint8_t *)"PIN/VERIFY", 10, verifier, 32);
    mbedtls_platform_zeroize(kver, sizeof(kver));
}

void pin_derive_session(const uint8_t *pin, size_t pin_len, uint8_t pin_token[32]) {
    uint8_t kver[32];
    derive_kver(pin, pin_len, kver);
    mbedtls_hkdf(SHA256(), pico_serial_hash, sizeof(pico_serial_hash), kver, 32, (const uint8_t *)"PIN/TOKEN", 9, pin_token, 32);
    mbedtls_platform_zeroize(kver, sizeof(kver));
}

void pin_derive_kenc(const uint8_t pin_token[32], uint8_t kenc[32]) {
    mbedtls_hkdf(SHA256(), pico_serial_hash, sizeof(pico_serial_hash), pin_token, 32, (const uint8_t *)"PIN/ENC", 7, kenc, 32);
}

void pin_derive_kenc2(const uint8_t pin_token[32], uint8_t kenc[32]) {
    uint8_t kbase[64];
    derive_kbase(kbase);
    memcpy(kbase + 32, pin_token, 32);
    mbedtls_hkdf(SHA256(), pico_serial_hash, sizeof(pico_serial_hash), kbase, 64, (const uint8_t *)"PIN/ENC2", 8, kenc, 32);
    mbedtls_platform_zeroize(kbase, sizeof(kbase));
}

// ------------------------------------------------------------------
// Encrypt 32-byte device key using AES-256-GCM
// Output: [nonce|ciphertext|tag]  =  12 + in_len + 16 = 60 bytes
// ------------------------------------------------------------------
int encrypt_with_aad(const uint8_t key[32], const uint8_t *in_buf, size_t in_len, const pin_kdf_version_t version, uint8_t *out_buf) {
    uint8_t *nonce = out_buf;
    uint8_t *ct    = out_buf + 12;
    uint8_t *tag   = out_buf + 12 + in_len;

    random_fill_buffer(nonce, 12);

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    uint8_t kenc[32];
    if (version == PIN_KDF_V2) {
        pin_derive_kenc2(key, kenc);
    }
    else if (version == PIN_KDF_V1) {
        pin_derive_kenc(key, kenc);
    }
    else {
        mbedtls_gcm_free(&gcm);
        return PICOKEYS_WRONG_DATA;
    }
    int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, kenc, 256);
    mbedtls_platform_zeroize(kenc, sizeof(kenc));
    if (rc != 0) {
        return rc;
    }

    rc = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, in_len, nonce, 12, pico_serial_hash, sizeof(pico_serial_hash), in_buf, ct, 16, tag);
    mbedtls_gcm_free(&gcm);
    return rc;
}

// ------------------------------------------------------------------
// Decrypt & verify 32-byte device key using AES-256-GCM
// Input: [nonce|ciphertext|tag]  =  in_len bytes
// Output: decrypted = in_len - 12 - 16 bytes
// ------------------------------------------------------------------
int decrypt_with_aad(const uint8_t key[32], const uint8_t *in_buf, size_t in_len, const pin_kdf_version_t version, uint8_t *out_buf) {
    const uint8_t *nonce = in_buf;
    const uint8_t *ct    = in_buf + 12;
    const uint8_t *tag   = in_buf + in_len - 16;

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    uint8_t kenc[32];
    if (version == PIN_KDF_V2) {
        pin_derive_kenc2(key, kenc);
    } else if (version == PIN_KDF_V1) {
        pin_derive_kenc(key, kenc);
    }
    else {
        mbedtls_gcm_free(&gcm);
        return PICOKEYS_WRONG_DATA;
    }
    int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, kenc, 256);
    mbedtls_platform_zeroize(kenc, sizeof(kenc));
    if (rc != 0) {
        return rc;
    }

    rc = mbedtls_gcm_auth_decrypt(&gcm, in_len - 16 - 12, nonce, 12, pico_serial_hash, sizeof(pico_serial_hash), tag, 16, ct, out_buf);
    mbedtls_gcm_free(&gcm);
    return rc;
}

// Old functions, kept for compatibility. NOT SECURE, use the new ones above.
void double_hash_pin(const uint8_t *pin, uint16_t len, uint8_t output[32]) {
    uint8_t o1[32];
    hash_multi(pin, len, o1);
    for (size_t i = 0; i < sizeof(o1); i++) {
        o1[i] ^= pin[i % len];
    }
    hash_multi(o1, sizeof(o1), output);
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
        mbedtls_aes_free(&aes);
        mbedtls_platform_zeroize(tmp_iv, sizeof(tmp_iv));
        return PICOKEYS_EXEC_ERROR;
    }
    int rc = 0;
    if (mode == PICOKEYS_AES_MODE_CBC) {
        rc = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, len, tmp_iv, data, data);
    }
    else {
        rc = mbedtls_aes_crypt_cfb128(&aes, MBEDTLS_AES_ENCRYPT, len, &iv_offset, tmp_iv, data, data);
    }
    mbedtls_aes_free(&aes);
    mbedtls_platform_zeroize(tmp_iv, sizeof(tmp_iv));
    return rc;
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
        mbedtls_aes_free(&aes);
        mbedtls_platform_zeroize(tmp_iv, sizeof(tmp_iv));
        return PICOKEYS_EXEC_ERROR;
    }
    int rc = 0;
    if (mode == PICOKEYS_AES_MODE_CBC) {
        rc = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, len, tmp_iv, data, data);
    }
    else {
        r = mbedtls_aes_setkey_enc(&aes, key, key_size); //CFB requires set_enc instead set_dec
        if (r != 0) {
            mbedtls_aes_free(&aes);
            mbedtls_platform_zeroize(tmp_iv, sizeof(tmp_iv));
            return PICOKEYS_EXEC_ERROR;
        }
        rc = mbedtls_aes_crypt_cfb128(&aes, MBEDTLS_AES_DECRYPT, len, &iv_offset, tmp_iv, data, data);
    }
    mbedtls_aes_free(&aes);
    mbedtls_platform_zeroize(tmp_iv, sizeof(tmp_iv));
    return rc;
}

int aes_encrypt_cfb_256(const uint8_t *key, const uint8_t *iv, uint8_t *data, uint16_t len) {
    return aes_encrypt(key, iv, 256, PICOKEYS_AES_MODE_CFB, data, len);
}
int aes_decrypt_cfb_256(const uint8_t *key, const uint8_t *iv, uint8_t *data, uint16_t len) {
    return aes_decrypt(key, iv, 256, PICOKEYS_AES_MODE_CFB, data, len);
}

PACK(struct lv_data {
    unsigned char *value;
    uint8_t len;
});

PACK(struct ec_curve_mbed_id {
    struct lv_data curve;
    mbedtls_ecp_group_id id;
});
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

#define POLY 0xedb88320

uint32_t crc32c(const uint8_t *buf, size_t len) {
    uint32_t crc = 0xffffffff;
    while (len--) {
        crc ^= *buf++;
        for (int k = 0; k < 8; k++) {
            crc = (crc >> 1) ^ (POLY & (0 - (crc & 1)));
        }
    }
    return ~crc;
}

int base64url_encode(unsigned char *dst, size_t dlen, size_t *olen, const unsigned char *src, size_t slen) {
    int rc = mbedtls_base64_encode(dst, dlen, olen, src, slen);
    if (rc != 0) {
        return rc;
    }
    for (size_t i = 0; i < *olen; i++) {
        if (dst[i] == '+') {
            dst[i] = '-';
        }
        else if (dst[i] == '/') {
            dst[i] = '_';
        }
    }
    if (*olen == 0) {
        return 0;
    }
    uint8_t *p = dst + *olen - 1;
    while (*p == '=') {
        *p-- = '\0';
        (*olen)--;
    }
    return 0;
}

int base64url_decode(unsigned char *dst, size_t dlen, size_t *olen, const unsigned char *src, size_t slen) {
    // First convert from base64url to standard base64
    if ((slen % 4) == 1) return MBEDTLS_ERR_BASE64_INVALID_CHARACTER;
    size_t padding = (4 - (slen % 4)) % 4;
    unsigned char *b64_src = malloc(slen + padding);
    if (b64_src == NULL) {
        return PICOKEYS_ERR_MEMORY_FATAL;
    }
    for (size_t i = 0; i < slen; i++) {
        if (src[i] == '-') {
            b64_src[i] = '+';
        }
        else if (src[i] == '_') {
            b64_src[i] = '/';
        }
        else {
            b64_src[i] = src[i];
        }
    }
    for (size_t i = 0; i < padding; i++) {
        b64_src[slen + i] = '=';
    }
    size_t b64_len = slen + padding;

    int rc = mbedtls_base64_decode(dst, dlen, olen, b64_src, b64_len);
    free(b64_src);
    return rc;
}

int b64url_decoded_len(size_t n, size_t *out_len) {
    if (out_len == NULL) return -1;
    if ((n % 4) == 1) return -2; // longitud base64url invàlida

    size_t pad = (4 - (n % 4)) % 4;   // 0,1,2
    size_t total = n + pad;
    size_t out = (total / 4) * 3;

    if (pad == 1) out -= 1;
    else if (pad == 2) out -= 2;

    *out_len = out;
    return 0;
}
