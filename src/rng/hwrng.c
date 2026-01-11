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

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#if defined(PICO_PLATFORM)
#include "pico/stdlib.h"
#include "hwrng.h"
#include "bsp/board.h"
#include "pico/rand.h"
#elif defined(ESP_PLATFORM)
#include "bootloader_random.h"
#include "esp_random.h"
#include "esp_compat.h"
#else
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include "board.h"
#endif

void hwrng_start() {
#if defined(ENABLE_EMULATION)
    srand(time(0));
#elif defined(ESP_PLATFORM)
    bootloader_random_enable();
#endif
}

static uint64_t random_word = 0xcbf29ce484222325;
static uint8_t hwrng_mix_round = 0;

static void hwrng_mix_init() {
    random_word = 0xcbf29ce484222325;
    hwrng_mix_round = 0;
}

/* Here, we assume a little endian architecture.  */
static int hwrng_mix_process() {
    if (hwrng_mix_round == 0) {
        hwrng_mix_init();
    }
    uint64_t word = 0x0;

#if defined(PICO_PLATFORM)
    word = get_rand_64();
#elif defined(ESP_PLATFORM)
    esp_fill_random((uint8_t *)&word, sizeof(word));
#else
    word = rand();
    word <<= 32;
    word |= rand();
#endif
    random_word ^= word ^ board_millis();
    random_word *= 0x00000100000001B3;
    if (++hwrng_mix_round == 8) {
        hwrng_mix_round = 0;
        return sizeof(uint64_t) / sizeof(uint32_t); //2 words
    }
    return 0;
}

struct hwrng_buf {
    uint32_t *buf;
    uint8_t head, tail;
    uint8_t size;
    unsigned int full : 1;
    unsigned int empty : 1;
};

static void hwrng_buf_init(struct hwrng_buf *rb, uint32_t *p, uint8_t size) {
    rb->buf = p;
    rb->size = size;
    rb->head = rb->tail = 0;
    rb->full = 0;
    rb->empty = 1;
}

static void hwrng_buf_add(struct hwrng_buf *rb, uint32_t v) {
    rb->buf[rb->tail++] = v;
    if (rb->tail == rb->size) {
        rb->tail = 0;
    }
    if (rb->tail == rb->head) {
        rb->full = 1;
    }
    rb->empty = 0;
}

static uint32_t hwrng_buf_del(struct hwrng_buf *rb) {
    uint32_t v = rb->buf[rb->head++];

    if (rb->head == rb->size) {
        rb->head = 0;
    }
    if (rb->head == rb->tail) {
        rb->empty = 1;
    }
    rb->full = 0;

    return v;
}

static struct hwrng_buf ring_buffer;

void *hwrng_task() {
    struct hwrng_buf *rb = &ring_buffer;

    int n;

    if ((n = hwrng_mix_process())) {
        const uint32_t *vp = (const uint32_t *) &random_word;

        for (int i = 0; i < n; i++) {
            hwrng_buf_add(rb, *vp++);
            if (rb->full) {
                break;
            }
        }
    }
    return NULL;
}

void hwrng_init(uint32_t *buf, uint8_t size) {
    struct hwrng_buf *rb = &ring_buffer;

    hwrng_buf_init(rb, buf, size);

    hwrng_start();

    hwrng_mix_init();
}

void hwrng_flush(void) {
    struct hwrng_buf *rb = &ring_buffer;
    while (!rb->empty) {
        hwrng_buf_del(rb);
    }
}

uint32_t hwrng_get() {
    struct hwrng_buf *rb = &ring_buffer;
    uint32_t v;

    while (rb->empty) {
        hwrng_task();
    }
    v = hwrng_buf_del(rb);

    return v;
}

void hwrng_wait_full() {
    struct hwrng_buf *rb = &ring_buffer;
#ifdef ESP_PLATFORM
    uint8_t core = xTaskGetCurrentTaskHandle() == hcore1 ? 1 : 0;
#elif defined(PICO_PLATFORM)
    uint core = get_core_num();
#endif
    while (!rb->full) {
#if defined(PICO_PLATFORM) || defined(ESP_PLATFORM)
        if (core == 1) {
            sleep_ms(1);
        }
        else
#endif
        hwrng_task();
    }
}
