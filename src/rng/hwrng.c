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
static uint8_t ep_round = 0;

static void ep_init() {
    random_word = 0xcbf29ce484222325;
    ep_round = 0;
}

/* Here, we assume a little endian architecture.  */
static int ep_process() {
    if (ep_round == 0) {
        ep_init();
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
    if (++ep_round == 8) {
        ep_round = 0;
        return 2; //2 words
    }
    return 0;
}

struct rng_rb {
    uint32_t *buf;
    uint8_t head, tail;
    uint8_t size;
    unsigned int full : 1;
    unsigned int empty : 1;
};

static void rb_init(struct rng_rb *rb, uint32_t *p, uint8_t size) {
    rb->buf = p;
    rb->size = size;
    rb->head = rb->tail = 0;
    rb->full = 0;
    rb->empty = 1;
}

static void rb_add(struct rng_rb *rb, uint32_t v) {
    rb->buf[rb->tail++] = v;
    if (rb->tail == rb->size) {
        rb->tail = 0;
    }
    if (rb->tail == rb->head) {
        rb->full = 1;
    }
    rb->empty = 0;
}

static uint32_t rb_del(struct rng_rb *rb) {
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

static struct rng_rb the_ring_buffer;

void *neug_task() {
    struct rng_rb *rb = &the_ring_buffer;

    int n;

    if ((n = ep_process())) {
        int i;
        const uint32_t *vp = (const uint32_t *) &random_word;

        for (i = 0; i < n; i++) {
            rb_add(rb, *vp++);
            if (rb->full) {
                break;
            }
        }
    }
    return NULL;
}

void neug_init(uint32_t *buf, uint8_t size) {
    struct rng_rb *rb = &the_ring_buffer;

    rb_init(rb, buf, size);

    hwrng_start();

    ep_init();
}

void neug_flush(void) {
    struct rng_rb *rb = &the_ring_buffer;

    while (!rb->empty) {
        rb_del(rb);
    }
}

uint32_t neug_get() {
    struct rng_rb *rb = &the_ring_buffer;
    uint32_t v;

    while (rb->empty) {
        neug_task();
    }
    v = rb_del(rb);

    return v;
}

void neug_wait_full() {
    struct rng_rb *rb = &the_ring_buffer;
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
        neug_task();
    }
}
