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

#define HWRNG_PRE_LOOP 32

#include "picokeys.h"
#include "hwrng.h"
#include "random.h"

#define RANDOM_BYTES_LENGTH 32
static uint8_t random_pool[256];

void random_init(void) {
    hwrng_init(random_pool, sizeof(random_pool));

    for (int i = 0; i < HWRNG_PRE_LOOP; i++) {
        hwrng_task();
    }
}

/*
 * Return pointer to random 32-byte
 */
#define MAX_RANDOM_BUFFER 1024
const uint8_t *random_bytes_get(size_t len) {
    if (len > MAX_RANDOM_BUFFER) {
        return NULL;
    }
    static uint8_t return_word[MAX_RANDOM_BUFFER];
    if (random_fill_buffer(return_word, len) != 0) {
        return NULL;
    }
    return (const uint8_t *) return_word;
}

/*
 * Random byte iterator
 */
int random_fill_iterator(void *arg, unsigned char *out, size_t out_len) {
    random_fill_iterator_ctx_t *ctx = (random_fill_iterator_ctx_t *) arg;
    int ret = 0;

    while (out_len) {
        if (ctx && ctx->cancel) {
            ret = -1;
            break;
        }
        size_t n = hwrng_read(out, out_len);
        if (n == 0) {
            hwrng_task();
            continue;
        }
        out += n;
        out_len -= n;
        if (ctx) {
            ctx->index = (uint8_t)((ctx->index + n) % RANDOM_BYTES_LENGTH);
        }
    }

    return ret;
}

int random_fill_buffer(uint8_t *buf, size_t n) {
    return random_fill_iterator(NULL, buf, n);
}
