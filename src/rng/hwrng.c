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
#include "hwrng.h"
#include "pico_time.h"

#if defined(PICO_PLATFORM)
#include "pico/rand.h"
#include "pico/mutex.h"
#elif defined(ESP_PLATFORM)
#include "bootloader_random.h"
#include "esp_random.h"
#include "compat/esp_compat.h"
#else
#include "compat/queue.h"
#endif

static void hwrng_start(void) {
#if defined(ENABLE_EMULATION)
    srand((unsigned int)time(NULL));
#elif defined(ESP_PLATFORM)
    bootloader_random_enable();
#endif
}

static uint64_t random_word = 0xcbf29ce484222325;
static uint8_t hwrng_mix_round = 0;

static void hwrng_mix_init(void) {
    random_word = 0xcbf29ce484222325;
    hwrng_mix_round = 0;
}

/* Here, we assume a little endian architecture.  */
static int hwrng_mix_process(void) {
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

static mutex_t hwrng_mutex;
static bool hwrng_mutex_initialized = false;

static inline void hwrng_lock(void) {
    if (hwrng_mutex_initialized) {
        mutex_enter_blocking(&hwrng_mutex);
    }
}

static inline void hwrng_unlock(void) {
    if (hwrng_mutex_initialized) {
        mutex_exit(&hwrng_mutex);
    }
}

static void hwrng_buf_init(struct hwrng_buf *rb, uint32_t *p, uint8_t size) {
    rb->buf = p;
    rb->size = size;
    rb->head = rb->tail = 0;
    rb->full = 0;
    rb->empty = 1;
}

static void hwrng_buf_add(struct hwrng_buf *rb, uint32_t v) {
    if (rb->full) {
        return;
    }

    uint8_t tail = rb->tail;
    rb->buf[tail] = v;
    tail++;
    if (tail >= rb->size) {
        tail = 0;
    }
    rb->tail = tail;
    rb->full = (rb->tail == rb->head);
    rb->empty = 0;
}

static uint32_t hwrng_buf_del(struct hwrng_buf *rb) {
    uint32_t v = 0;
    if (rb->empty) {
        return v;
    }

    uint8_t head = rb->head;
    v = rb->buf[head];
    head++;
    if (head >= rb->size) {
        head = 0;
    }
    rb->head = head;
    if (rb->head == rb->tail) {
        rb->empty = 1;
    }
    rb->full = 0;

    return v;
}

static struct hwrng_buf ring_buffer;

void *hwrng_task(void) {
    struct hwrng_buf *rb = &ring_buffer;

    int n;

    hwrng_lock();
    if ((n = hwrng_mix_process())) {
        const uint32_t *vp = (const uint32_t *) &random_word;

        for (int i = 0; i < n; i++) {
            hwrng_buf_add(rb, *vp++);
            if (rb->full) {
                break;
            }
        }
    }
    hwrng_unlock();
    return NULL;
}

void hwrng_init(uint32_t *buf, uint8_t size) {
    struct hwrng_buf *rb = &ring_buffer;

    mutex_init(&hwrng_mutex);
    hwrng_mutex_initialized = true;
    hwrng_buf_init(rb, buf, size);

    hwrng_start();

    hwrng_mix_init();
}

void hwrng_flush(void) {
    struct hwrng_buf *rb = &ring_buffer;
    hwrng_lock();
    while (!rb->empty) {
        hwrng_buf_del(rb);
    }
    hwrng_unlock();
}

uint32_t hwrng_get(void) {
    struct hwrng_buf *rb = &ring_buffer;
    uint32_t v;

    while (true) {
        hwrng_lock();
        if (!rb->empty) {
            v = hwrng_buf_del(rb);
            hwrng_unlock();
            break;
        }
        hwrng_unlock();
        hwrng_task();
    }

    return v;
}

void hwrng_wait_full(void) {
    struct hwrng_buf *rb = &ring_buffer;
#ifdef ESP_PLATFORM
    uint8_t core = xTaskGetCurrentTaskHandle() == hcore1 ? 1 : 0;
#elif defined(PICO_PLATFORM)
    uint core = get_core_num();
#endif
    while (true) {
        hwrng_lock();
        hwrng_unlock();
        if (rb->full) {
            break;
        }
#if defined(PICO_PLATFORM) || defined(ESP_PLATFORM)
        if (core == 1) {
            sleep_ms(1);
        }
        else
#endif
        hwrng_task();
    }
}
