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

#ifndef _CRYPTO_UTILS_H_
#define _CRYPTO_UTILS_H_

#include "mbedtls/ecp.h"
#include "mbedtls/md.h"

#define PICOKEYS_KEY_RSA                 0x000f // It is a mask
#define PICOKEYS_KEY_RSA_1K              0x0001
#define PICOKEYS_KEY_RSA_2K              0x0002
#define PICOKEYS_KEY_RSA_3K              0x0004
#define PICOKEYS_KEY_RSA_4k              0x0008
#define PICOKEYS_KEY_EC                  0x0010
#define PICOKEYS_KEY_AES                 0x0f00 // It is a mask
#define PICOKEYS_KEY_AES_128             0x0100
#define PICOKEYS_KEY_AES_192             0x0200
#define PICOKEYS_KEY_AES_256             0x0400
#define PICOKEYS_KEY_AES_512             0x0800 /* For AES XTS */

#define PICOKEYS_AES_MODE_CBC            1
#define PICOKEYS_AES_MODE_CFB            2

#define IV_SIZE 16

typedef enum {
    PIN_KDF_V1 = 1,
    PIN_KDF_V2 = 2,
    PIN_KDF_UNKNOWN = 0xff
} pin_kdf_version_t;

#define PIN_KDF_DEFAULT_VERSION PIN_KDF_V2

// Newer and safe functions
extern void derive_kbase(uint8_t kbase[32]);
extern void derive_kver(const uint8_t *pin, size_t pin_len, uint8_t kver[32]);
extern void pin_derive_kenc(const uint8_t pin_token[32], uint8_t kenc[32]);
extern void pin_derive_kenc2(const uint8_t pin_token[32], uint8_t kenc[32]);
extern void pin_derive_session(const uint8_t *pin, size_t pin_len, uint8_t pin_token[32]);
extern void pin_derive_verifier(const uint8_t *pin, size_t pin_len, uint8_t verifier[32]);
extern int encrypt_with_aad(const uint8_t key[32], const uint8_t *in_buf, size_t in_len, const pin_kdf_version_t version, uint8_t *out_buf);
extern int decrypt_with_aad(const uint8_t key[32], const uint8_t *in_buf, size_t in_len, const pin_kdf_version_t version, uint8_t *out_buf);
extern void double_hash_pin(const uint8_t *pin, uint16_t len, uint8_t output[32]);
extern void hash_multi(const uint8_t *input, uint16_t len, uint8_t output[32]);
extern void hash256(const uint8_t *input, size_t len, uint8_t output[32]);
extern void generic_hash(mbedtls_md_type_t md, const uint8_t *input, size_t len, uint8_t *output);
extern int aes_encrypt(const uint8_t *key, const uint8_t *iv, uint16_t key_size, int mode, uint8_t *data, uint16_t len);
extern int aes_decrypt(const uint8_t *key, const uint8_t *iv, uint16_t key_size, int mode, uint8_t *data, uint16_t len);
extern int aes_encrypt_cfb_256(const uint8_t *key, const uint8_t *iv, uint8_t *data, uint16_t len);
extern int aes_decrypt_cfb_256(const uint8_t *key, const uint8_t *iv, uint8_t *data, uint16_t len);
extern mbedtls_ecp_group_id ec_get_curve_from_prime(const uint8_t *prime, size_t prime_len);
extern uint32_t crc32c(const uint8_t *buf, size_t len);
extern int base64url_encode(unsigned char *dst, size_t dlen, size_t *olen, const unsigned char *src, size_t slen);
extern int base64url_decode(unsigned char *dst, size_t dlen, size_t *olen, const unsigned char *src, size_t slen);
extern int b64url_decoded_len(size_t n, size_t *out_len);

#define PIN_KDF_SIZE(x)  (12 + (x) + 16)

#endif
