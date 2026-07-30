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
#include "eac.h"
#include "crypto_utils.h"
#include "random.h"
#include "mbedtls/cmac.h"
#include "tlv.h"
#include "apdu.h"
#ifdef ENABLE_EMULATION
#include "usb/emulation/emulation.h"
#else
#include "usb/usb.h"
#endif
#include "mbedtls/constant_time.h"

static uint8_t sm_nonce[8];
static uint8_t sm_kmac[16];
static uint8_t sm_kenc[16];
static MSE_protocol sm_protocol = MSE_NONE;
static mbedtls_mpi sm_mSSC;
static uint8_t sm_blocksize = 0;
static uint8_t sm_iv[16];
static bool sm_active = false;

bool is_secured_apdu(void) {
    return CLA(apdu) & 0xC;
}

static void sm_derive_key(const_byte_array_t input, uint8_t counter, const_byte_array_t nonce, byte_array_t output) {
    uint8_t *b = (uint8_t *) calloc(1, input.len + nonce.len + 4);
    if (input.data) {
        memcpy(b, input.data, input.len);
    }
    if (nonce.data) {
        memcpy(b + input.len, nonce.data, nonce.len);
    }
    b[input.len + nonce.len + 3] = counter;
    uint8_t digest[20];
    generic_hash(MBEDTLS_MD_SHA1, CONST_BYTE_ARRAY(b, input.len + nonce.len + 4), digest);
    memcpy(output.data, digest, output.len);
    free(b);
}

void sm_derive_all_keys(const_byte_array_t derived) {
    memcpy(sm_nonce, random_bytes_get(8), 8);
    sm_derive_key(derived, 1, CONST_BYTE_ARRAY(sm_nonce, sizeof(sm_nonce)), BYTE_ARRAY(sm_kenc, sizeof(sm_kenc)));
    sm_derive_key(derived, 2, CONST_BYTE_ARRAY(sm_nonce, sizeof(sm_nonce)), BYTE_ARRAY(sm_kmac, sizeof(sm_kmac)));
    mbedtls_mpi_free(&sm_mSSC);
    mbedtls_mpi_init(&sm_mSSC);
    mbedtls_mpi_grow(&sm_mSSC, sm_blocksize);
    mbedtls_mpi_lset(&sm_mSSC, 0);
    memset(sm_iv, 0, sizeof(sm_iv));
    sm_active = true;
}

void sm_set_protocol(MSE_protocol proto) {
    sm_protocol = proto;
    if (proto == MSE_AES) {
        sm_blocksize = 16;
    }
    else if (proto == MSE_3DES) {
        sm_blocksize = 8;
    }
    else {
        sm_blocksize = 0;
    }
    memset(sm_kenc, 0, sizeof(sm_kenc));
    memset(sm_kmac, 0, sizeof(sm_kmac));
    memset(sm_nonce, 0, sizeof(sm_nonce));
    memset(sm_iv, 0, sizeof(sm_iv));
    sm_active = false;
}

MSE_protocol sm_get_protocol(void) {
    return sm_protocol;
}

uint8_t *sm_get_nonce(void) {
    return sm_nonce;
}

int sm_sign(const_byte_array_t input, uint8_t out[16]) {
    return mbedtls_cipher_cmac(mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB), sm_kmac, 128, input.data, input.len, out);
}

int sm_unwrap(void) {
    uint8_t sm_indicator = (CLA(apdu) >> 2) & 0x3;
    if (sm_indicator == 0) {
        return PICOKEYS_OK;
    }
    if (!sm_active || sm_blocksize == 0) {
        return PICOKEYS_EXEC_ERROR;
    }
    int r = sm_verify();
    if (r != PICOKEYS_OK) {
        return r;
    }
    apdu.ne = sm_get_le();

    uint8_t *body = NULL;
    uint16_t body_size = 0;
    bool is87 = false;
    uint8_t *p = NULL;
    tlv_item_t item;
    tlv_ctx_t ctxi;
    tlv_ctx_init(BYTE_ARRAY(apdu.data, (uint16_t)apdu.nc), &ctxi);
    while (tlv_walk(&ctxi, &p, &item)) {
        if (item.tag == 0x87 || item.tag == 0x85) {
            body = (uint8_t *)item.value.data;
            body_size = (uint16_t)item.value.len;
            if (item.tag == 0x87) {
                if (body_size == 0) {
                    return PICOKEYS_WRONG_LENGTH;
                }
                is87 = true;
                body_size--;
            }
        }
    }
    if (!body) {
        apdu.nc = 0;
        return PICOKEYS_OK;
    }
    if (is87 && *body++ != 0x1) {
        return PICOKEYS_WRONG_PADDING;
    }
    if (body_size == 0 || body_size % sm_blocksize != 0) {
        return PICOKEYS_WRONG_LENGTH;
    }
    sm_update_iv();
    aes_decrypt(CONST_BYTE_ARRAY(sm_kenc, sizeof(sm_kenc)), sm_iv, PICOKEYS_AES_MODE_CBC, BYTE_ARRAY(body, body_size));
    memmove(apdu.data, body, body_size);
    apdu.nc = sm_remove_padding(CONST_BYTE_ARRAY(apdu.data, body_size));
    DEBUG_PAYLOAD(apdu.data, (int) apdu.nc);
    return PICOKEYS_OK;
}

int sm_wrap(void) {
    uint8_t sm_indicator = (CLA(apdu) >> 2) & 0x3;
    if (sm_indicator == 0) {
        return PICOKEYS_OK;
    }
    if (!sm_active || sm_blocksize == 0) {
        return PICOKEYS_EXEC_ERROR;
    }
    size_t encrypted_size = 0;
    size_t response_size = 4 + 10; // DO99 and DO8E
    if (res_APDU_size > 0) {
        encrypted_size = res_APDU_size + 1;
        encrypted_size += sm_blocksize - (encrypted_size % sm_blocksize);
        response_size += 1 + tlv_format_len((uint16_t)(encrypted_size + 1), NULL) + encrypted_size + 1;
    }
    if (response_size > USB_BUFFER_SIZE - 20) {
        return PICOKEYS_WRONG_LENGTH;
    }
    size_t mac_input_size = sm_blocksize + response_size - 10;
    mac_input_size += sm_blocksize - (mac_input_size % sm_blocksize);
    if (mac_input_size > USB_BUFFER_SIZE) {
        return PICOKEYS_WRONG_LENGTH;
    }

    uint8_t input[USB_BUFFER_SIZE];
    size_t input_len = 0;
    memset(input, 0, sizeof(input));
    mbedtls_mpi ssc;
    mbedtls_mpi_init(&ssc);
    mbedtls_mpi_add_int(&ssc, &sm_mSSC, 1);
    mbedtls_mpi_copy(&sm_mSSC, &ssc);
    int r = mbedtls_mpi_write_binary(&ssc, input, sm_blocksize);
    if (r != 0) {
        return PICOKEYS_EXEC_ERROR;
    }
    input_len += sm_blocksize;
    mbedtls_mpi_free(&ssc);
    if (res_APDU_size > 0) {
        res_APDU[res_APDU_size++] = 0x80;
        memset(res_APDU + res_APDU_size, 0, (sm_blocksize - (res_APDU_size % sm_blocksize)));
        res_APDU_size += (sm_blocksize - (res_APDU_size % sm_blocksize));
        DEBUG_PAYLOAD(res_APDU, res_APDU_size);
        sm_update_iv();
        aes_encrypt(CONST_BYTE_ARRAY(sm_kenc, sizeof(sm_kenc)), sm_iv, PICOKEYS_AES_MODE_CBC, BYTE_ARRAY(res_APDU, res_APDU_size));
        memmove(res_APDU + 1, res_APDU, res_APDU_size);
        res_APDU[0] = 0x1;
        res_APDU_size++;
        if (res_APDU_size < 128) {
            memmove(res_APDU + 2, res_APDU, res_APDU_size);
            res_APDU[1] = (uint8_t)res_APDU_size;
            res_APDU_size += 2;
        }
        else if (res_APDU_size < 256) {
            memmove(res_APDU + 3, res_APDU, res_APDU_size);
            res_APDU[1] = 0x81;
            res_APDU[2] = (uint8_t)res_APDU_size;
            res_APDU_size += 3;
        }
        else {
            memmove(res_APDU + 4, res_APDU, res_APDU_size);
            res_APDU[1] = 0x82;
            put_uint16_be(res_APDU_size, res_APDU + 2);
            res_APDU_size += 4;
        }
        res_APDU[0] = 0x87;
    }
    res_APDU[res_APDU_size++] = 0x99;
    res_APDU[res_APDU_size++] = 2;
    put_uint16_be(apdu.sw, res_APDU + res_APDU_size);
    res_APDU_size += 2;
    memcpy(input + input_len, res_APDU, res_APDU_size);
    input_len += res_APDU_size;
    input[input_len++] = 0x80;
    input_len += (sm_blocksize - (input_len % sm_blocksize));
    r = sm_sign(CONST_BYTE_ARRAY(input, input_len), res_APDU + res_APDU_size + 2);
    res_APDU[res_APDU_size++] = 0x8E;
    res_APDU[res_APDU_size++] = 8;
    res_APDU_size += 8;
    if (apdu.ne > 0) {
        apdu.ne = res_APDU_size;
    }
    set_res_sw(0x90, 0x00);
    return PICOKEYS_OK;
}

uint16_t sm_get_le(void) {
    uint8_t *p = NULL;
    tlv_item_t item;
    tlv_ctx_t ctxi;
    tlv_ctx_init(BYTE_ARRAY(apdu.data, (uint16_t)apdu.nc), &ctxi);
    while (tlv_walk(&ctxi, &p, &item)) {
        if (item.tag == 0x97) {
            uint16_t le = 0;
            for (size_t t = 1; t <= item.value.len; t++) {
                le |= (item.value.data[t - 1]) << ((item.value.len - t) * 8);
            }
            return le;
        }
    }
    return 0;
}

void sm_update_iv(void) {
    uint8_t tmp_iv[16], sc_counter[16];
    memset(tmp_iv, 0, sizeof(tmp_iv)); //IV is always 0 for encryption of IV based on counter
    mbedtls_mpi_write_binary(&sm_mSSC, sc_counter, sizeof(sc_counter));
    aes_encrypt(CONST_BYTE_ARRAY(sm_kenc, sizeof(sm_kenc)), tmp_iv, PICOKEYS_AES_MODE_CBC, BYTE_ARRAY(sc_counter, sizeof(sc_counter)));
    memcpy(sm_iv, sc_counter, sizeof(sc_counter));
}

int sm_verify(void) {
    uint8_t input[USB_BUFFER_SIZE];
    memset(input, 0, sizeof(input));
    size_t input_len = 0;
    int r = 0;
    bool add_header = (CLA(apdu) & 0xC) == 0xC;
    size_t data_len = (size_t)(apdu.nc / sm_blocksize) * sm_blocksize;
    if (data_len % sm_blocksize) {
        data_len += sm_blocksize;
    }
    if (data_len + (add_header ? sm_blocksize : 0) > sizeof(input)) {
        return PICOKEYS_WRONG_LENGTH;
    }
    mbedtls_mpi ssc;
    mbedtls_mpi_init(&ssc);
    mbedtls_mpi_add_int(&ssc, &sm_mSSC, 1);
    mbedtls_mpi_copy(&sm_mSSC, &ssc);
    r = mbedtls_mpi_write_binary(&ssc, input, sm_blocksize);
    input_len += sm_blocksize;
    mbedtls_mpi_free(&ssc);
    if (r != 0) {
        return PICOKEYS_EXEC_ERROR;
    }
    if (add_header) {
        input[input_len++] = CLA(apdu);
        input[input_len++] = INS(apdu);
        input[input_len++] = P1(apdu);
        input[input_len++] = P2(apdu);
        input[input_len++] = 0x80;
        input_len += sm_blocksize - 5;
    }
    bool some_added = false;
    const uint8_t *mac = NULL;
    size_t mac_len = 0;
    uint8_t *p = NULL;
    tlv_item_t item;
    tlv_ctx_t ctxi;
    tlv_ctx_init(BYTE_ARRAY(apdu.data, (uint16_t)apdu.nc), &ctxi);
    while (tlv_walk(&ctxi, &p, &item)) {
        if (item.tag & 0x1) {
            size_t encoded_len = 1 + tlv_format_len((uint16_t)item.value.len, NULL) + item.value.len;
            if (encoded_len > sizeof(input) - input_len) {
                return PICOKEYS_WRONG_LENGTH;
            }
            input[input_len++] = (uint8_t)item.tag;
            uint8_t tlen = tlv_format_len((uint16_t)item.value.len, input + input_len);
            input_len += tlen;
            memcpy(input + input_len, item.value.data, item.value.len);
            input_len += item.value.len;
            some_added = true;
        }
        if (item.tag == 0x8E) {
            mac = item.value.data;
            mac_len = item.value.len;
        }
    }
    if (!mac || mac_len != 8) {
        return PICOKEYS_WRONG_DATA;
    }
    if (some_added) {
        size_t padding_len = sm_blocksize - (input_len % sm_blocksize);
        if (padding_len > sizeof(input) - input_len) {
            return PICOKEYS_WRONG_LENGTH;
        }
        input[input_len++] = 0x80;
        input_len += padding_len - 1;
    }
    uint8_t signature[16];
    r = sm_sign(CONST_BYTE_ARRAY(input, input_len), signature);
    if (r != 0) {
        return PICOKEYS_EXEC_ERROR;
    }
    if (mbedtls_ct_memcmp(signature, mac, mac_len) == 0) {
        return PICOKEYS_OK;
    }
    return PICOKEYS_VERIFICATION_FAILED;
}

uint16_t sm_remove_padding(const_byte_array_t data) {
    if (data.len == 0 || data.len > UINT16_MAX || data.data == NULL) {
        return 0;
    }

    int32_t i = (int32_t)data.len - 1;
    for (; i >= 0 && data.data[i] == 0; i--) {
        ;
    }
    if (i < 0 || data.data[i] != 0x80) {
        return 0;
    }
    return (uint16_t)i;
}
