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

#ifndef _CRYPTO_UTILS_H_
#define _CRYPTO_UTILS_H_

#include "mbedtls/ecp.h"
#include "mbedtls/md.h"

#define PICO_KEYS_KEY_RSA                 0x000f // It is a mask
#define PICO_KEYS_KEY_RSA_1K              0x0001
#define PICO_KEYS_KEY_RSA_2K              0x0002
#define PICO_KEYS_KEY_RSA_3K              0x0004
#define PICO_KEYS_KEY_RSA_4k              0x0008
#define PICO_KEYS_KEY_EC                  0x0010
#define PICO_KEYS_KEY_AES                 0x0f00 // It is a mask
#define PICO_KEYS_KEY_AES_128             0x0100
#define PICO_KEYS_KEY_AES_192             0x0200
#define PICO_KEYS_KEY_AES_256             0x0400
#define PICO_KEYS_KEY_AES_512             0x0800 /* For AES XTS */

#define PICO_KEYS_AES_MODE_CBC            1
#define PICO_KEYS_AES_MODE_CFB            2

#define IV_SIZE 16

extern void double_hash_pin(const uint8_t *pin, uint16_t len, uint8_t output[32]);
extern void hash_multi(const uint8_t *input, uint16_t len, uint8_t output[32]);
extern void hash256(const uint8_t *input, size_t len, uint8_t output[32]);
extern void generic_hash(mbedtls_md_type_t md, const uint8_t *input, size_t len, uint8_t *output);
extern int aes_encrypt(const uint8_t *key,
                       const uint8_t *iv,
                       int key_size,
                       int mode,
                       uint8_t *data,
                       int len);
extern int aes_decrypt(const uint8_t *key,
                       const uint8_t *iv,
                       int key_size,
                       int mode,
                       uint8_t *data,
                       int len);
extern int aes_encrypt_cfb_256(const uint8_t *key, const uint8_t *iv, uint8_t *data, int len);
extern int aes_decrypt_cfb_256(const uint8_t *key, const uint8_t *iv, uint8_t *data, int len);
extern mbedtls_ecp_group_id ec_get_curve_from_prime(const uint8_t *prime, size_t prime_len);

#endif
