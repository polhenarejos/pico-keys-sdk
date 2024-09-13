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

#include "common.h"
#include "mbedtls/sha256.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "pico/sha256.h"

#define SHA256_BLOCK_SIZE 64

static const uint32_t K[] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
};

#define SHR(x, n) (((x) & 0xFFFFFFFF) >> (n))
#define ROTR(x, n) (SHR(x, n) | ((x) << (32 - (n))))
#define S0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^  SHR(x, 3))
#define S1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^  SHR(x, 10))
#define S2(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S3(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define F0(x, y, z) (((x) & (y)) | ((z) & ((x) | (y))))
#define F1(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))

#define R(t)                                                        \
    (                                                               \
        local.W[t] = S1(local.W[(t) -  2]) + local.W[(t) -  7] +    \
                     S0(local.W[(t) - 15]) + local.W[(t) - 16]      \
    )

#define P(a, b, c, d, e, f, g, h, x, K)                                      \
    do                                                              \
    {                                                               \
        local.temp1 = (h) + S3(e) + F1((e), (f), (g)) + (K) + (x);    \
        local.temp2 = S2(a) + F0((a), (b), (c));                      \
        (d) += local.temp1; (h) = local.temp1 + local.temp2;        \
    } while (0)


void mbedtls_sha256_init(mbedtls_sha256_context *ctx) {
    memset(ctx, 0, sizeof(mbedtls_sha256_context));
}

void mbedtls_sha256_free(mbedtls_sha256_context *ctx) {
    if (ctx == NULL) {
        return;
    }

    mbedtls_platform_zeroize(ctx, sizeof(mbedtls_sha256_context));
}

int mbedtls_sha256_starts(mbedtls_sha256_context *ctx, int is224) {
    ctx->is224 = is224;
    if (is224 == 1) {
        ctx->total[0] = 0;
        ctx->total[1] = 0;

        ctx->state[0] = 0xC1059ED8;
        ctx->state[1] = 0x367CD507;
        ctx->state[2] = 0x3070DD17;
        ctx->state[3] = 0xF70E5939;
        ctx->state[4] = 0xFFC00B31;
        ctx->state[5] = 0x68581511;
        ctx->state[6] = 0x64F98FA7;
        ctx->state[7] = 0xBEFA4FA4;
    }
    else {
        return pico_sha256_start_blocking(&ctx->pico_state, SHA256_BIG_ENDIAN, true);
    }
    return 0;
}

static int mbedtls_internal_sha256_process_c(mbedtls_sha256_context *ctx, const unsigned char data[SHA256_BLOCK_SIZE]) {
    struct {
        uint32_t temp1, temp2, W[64];
        uint32_t A[8];
    } local;

    unsigned int i;

    for (i = 0; i < 8; i++) {
        local.A[i] = ctx->state[i];
    }

    for (i = 0; i < 16; i++) {
        local.W[i] = MBEDTLS_GET_UINT32_BE(data, 4 * i);
    }

    for (i = 0; i < 16; i += 8) {
        P(local.A[0], local.A[1], local.A[2], local.A[3], local.A[4],
          local.A[5], local.A[6], local.A[7], local.W[i+0], K[i+0]);
        P(local.A[7], local.A[0], local.A[1], local.A[2], local.A[3],
          local.A[4], local.A[5], local.A[6], local.W[i+1], K[i+1]);
        P(local.A[6], local.A[7], local.A[0], local.A[1], local.A[2],
          local.A[3], local.A[4], local.A[5], local.W[i+2], K[i+2]);
        P(local.A[5], local.A[6], local.A[7], local.A[0], local.A[1],
          local.A[2], local.A[3], local.A[4], local.W[i+3], K[i+3]);
        P(local.A[4], local.A[5], local.A[6], local.A[7], local.A[0],
          local.A[1], local.A[2], local.A[3], local.W[i+4], K[i+4]);
        P(local.A[3], local.A[4], local.A[5], local.A[6], local.A[7],
          local.A[0], local.A[1], local.A[2], local.W[i+5], K[i+5]);
        P(local.A[2], local.A[3], local.A[4], local.A[5], local.A[6],
          local.A[7], local.A[0], local.A[1], local.W[i+6], K[i+6]);
        P(local.A[1], local.A[2], local.A[3], local.A[4], local.A[5],
          local.A[6], local.A[7], local.A[0], local.W[i+7], K[i+7]);
    }

    for (i = 16; i < 64; i += 8) {
        P(local.A[0], local.A[1], local.A[2], local.A[3], local.A[4],
          local.A[5], local.A[6], local.A[7], R(i+0), K[i+0]);
        P(local.A[7], local.A[0], local.A[1], local.A[2], local.A[3],
          local.A[4], local.A[5], local.A[6], R(i+1), K[i+1]);
        P(local.A[6], local.A[7], local.A[0], local.A[1], local.A[2],
          local.A[3], local.A[4], local.A[5], R(i+2), K[i+2]);
        P(local.A[5], local.A[6], local.A[7], local.A[0], local.A[1],
          local.A[2], local.A[3], local.A[4], R(i+3), K[i+3]);
        P(local.A[4], local.A[5], local.A[6], local.A[7], local.A[0],
          local.A[1], local.A[2], local.A[3], R(i+4), K[i+4]);
        P(local.A[3], local.A[4], local.A[5], local.A[6], local.A[7],
          local.A[0], local.A[1], local.A[2], R(i+5), K[i+5]);
        P(local.A[2], local.A[3], local.A[4], local.A[5], local.A[6],
          local.A[7], local.A[0], local.A[1], R(i+6), K[i+6]);
        P(local.A[1], local.A[2], local.A[3], local.A[4], local.A[5],
          local.A[6], local.A[7], local.A[0], R(i+7), K[i+7]);
    }

    for (i = 0; i < 8; i++) {
        ctx->state[i] += local.A[i];
    }

    /* Zeroise buffers and variables to clear sensitive data from memory. */
    mbedtls_platform_zeroize(&local, sizeof(local));

    return 0;
}

static size_t mbedtls_internal_sha256_process_many_c(mbedtls_sha256_context *ctx, const uint8_t *data, size_t len) {
    size_t processed = 0;

    while (len >= SHA256_BLOCK_SIZE) {
        if (mbedtls_internal_sha256_process_c(ctx, data) != 0) {
            return 0;
        }

        data += SHA256_BLOCK_SIZE;
        len  -= SHA256_BLOCK_SIZE;

        processed += SHA256_BLOCK_SIZE;
    }

    return processed;
}

int mbedtls_sha256_update(mbedtls_sha256_context *ctx, const unsigned char *input, size_t ilen) {

    if (ctx->is224 == 1) {
        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        size_t fill;
        uint32_t left;

        if (ilen == 0) {
            return 0;
        }

        left = ctx->total[0] & 0x3F;
        fill = SHA256_BLOCK_SIZE - left;

        ctx->total[0] += (uint32_t) ilen;
        ctx->total[0] &= 0xFFFFFFFF;

        if (ctx->total[0] < (uint32_t) ilen) {
            ctx->total[1]++;
        }

        if (left && ilen >= fill) {
            memcpy((void *) (ctx->buffer + left), input, fill);

            if ((ret = mbedtls_internal_sha256_process_c(ctx, ctx->buffer)) != 0) {
                return ret;
            }

            input += fill;
            ilen  -= fill;
            left = 0;
        }

        while (ilen >= SHA256_BLOCK_SIZE) {
            size_t processed = mbedtls_internal_sha256_process_many_c(ctx, input, ilen);
            if (processed < SHA256_BLOCK_SIZE) {
                return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
            }

            input += processed;
            ilen  -= processed;
        }

        if (ilen > 0) {
            memcpy((void *) (ctx->buffer + left), input, ilen);
        }
    }
    else {
        pico_sha256_update_blocking(&ctx->pico_state, (const uint8_t *)input, ilen);
    }
    return 0;
}

int mbedtls_sha256_finish(mbedtls_sha256_context *ctx, unsigned char *output) {
    if (ctx->is224) {
        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        uint32_t used;
        uint32_t high, low;

        used = ctx->total[0] & 0x3F;

        ctx->buffer[used++] = 0x80;

        if (used <= 56) {
            memset(ctx->buffer + used, 0, 56 - used);
        } else {
            memset(ctx->buffer + used, 0, SHA256_BLOCK_SIZE - used);

            if ((ret = mbedtls_internal_sha256_process_c(ctx, ctx->buffer)) != 0) {
                goto exit;
            }

            memset(ctx->buffer, 0, 56);
        }

        high = (ctx->total[0] >> 29) | (ctx->total[1] <<  3);
        low  = (ctx->total[0] <<  3);

        MBEDTLS_PUT_UINT32_BE(high, ctx->buffer, 56);
        MBEDTLS_PUT_UINT32_BE(low,  ctx->buffer, 60);

        if ((ret = mbedtls_internal_sha256_process_c(ctx, ctx->buffer)) != 0) {
            goto exit;
        }

        MBEDTLS_PUT_UINT32_BE(ctx->state[0], output,  0);
        MBEDTLS_PUT_UINT32_BE(ctx->state[1], output,  4);
        MBEDTLS_PUT_UINT32_BE(ctx->state[2], output,  8);
        MBEDTLS_PUT_UINT32_BE(ctx->state[3], output, 12);
        MBEDTLS_PUT_UINT32_BE(ctx->state[4], output, 16);
        MBEDTLS_PUT_UINT32_BE(ctx->state[5], output, 20);
        MBEDTLS_PUT_UINT32_BE(ctx->state[6], output, 24);

        ret = 0;

    exit:
        mbedtls_sha256_free(ctx);
        return ret;
    }
    else {
        sha256_result_t result;
        pico_sha256_finish(&ctx->pico_state, &result);
        memcpy(output, result.bytes, 32);
    }
    return 0;
}
