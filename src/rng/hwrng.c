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

typedef struct hwrng_buf {
    uint8_t *buf;
    size_t head;
    size_t tail;
    size_t size;
    size_t count;
} hwrng_buf_t;

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

static void hwrng_buf_init(struct hwrng_buf *rb, uint8_t *p, size_t size) {
    rb->buf = p;
    rb->size = size;
    rb->head = rb->tail = 0;
    rb->count = 0;
}

static size_t hwrng_buf_add(struct hwrng_buf *rb, const uint8_t *data, size_t len) {
    size_t room = rb->size - rb->count;
    size_t n = len < room ? len : room;
    size_t tail = rb->tail;
    size_t first = n;

    if (first > rb->size - tail) {
        first = rb->size - tail;
    }
    if (first) {
        memcpy(rb->buf + tail, data, first);
        tail += first;
        if (tail >= rb->size) {
            tail = 0;
        }
    }
    if (n > first) {
        size_t second = n - first;
        memcpy(rb->buf + tail, data + first, second);
        tail += second;
    }
    rb->tail = tail;
    rb->count += n;
    return n;
}

static size_t hwrng_buf_del(struct hwrng_buf *rb, uint8_t *data, size_t len) {
    size_t n = len < rb->count ? len : rb->count;
    size_t head = rb->head;
    size_t first = n;

    if (first > rb->size - head) {
        first = rb->size - head;
    }
    if (first) {
        memcpy(data, rb->buf + head, first);
        head += first;
        if (head >= rb->size) {
            head = 0;
        }
    }
    if (n > first) {
        size_t second = n - first;
        memcpy(data + first, rb->buf + head, second);
        head += second;
    }
    rb->head = head;
    rb->count -= n;
    return n;
}

static inline size_t hwrng_buf_space(const struct hwrng_buf *rb) {
    return rb->size - rb->count;
}

static inline bool hwrng_buf_full(const struct hwrng_buf *rb) {
    return rb->count == rb->size;
}

static struct hwrng_buf ring_buffer;

void *hwrng_task(void) {
    struct hwrng_buf *rb = &ring_buffer;

    hwrng_lock();
    if (hwrng_buf_space(rb) >= sizeof(random_word) && hwrng_mix_process()) {
        hwrng_buf_add(rb, (const uint8_t *)&random_word, sizeof(random_word));
    }
    hwrng_unlock();
    return NULL;
}

void hwrng_init(uint8_t *buf, size_t size) {
    struct hwrng_buf *rb = &ring_buffer;

    mutex_init(&hwrng_mutex);
    hwrng_mutex_initialized = true;
    hwrng_buf_init(rb, buf, size);

    hwrng_start();

    hwrng_mix_init();
}

size_t hwrng_read(uint8_t *buf, size_t len) {
    struct hwrng_buf *rb = &ring_buffer;
    size_t n;

    hwrng_lock();
    n = hwrng_buf_del(rb, buf, len);
    hwrng_unlock();
    return n;
}

void hwrng_flush(void) {
    struct hwrng_buf *rb = &ring_buffer;
    hwrng_lock();
    rb->head = 0;
    rb->tail = 0;
    rb->count = 0;
    hwrng_unlock();
}

uint32_t hwrng_get(void) {
    uint32_t v = 0;
    size_t offset = 0;

    while (offset < sizeof(v)) {
        size_t n = hwrng_read(((uint8_t *)&v) + offset, sizeof(v) - offset);
        if (n == 0) {
            hwrng_task();
            continue;
        }
        offset += n;
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
        bool full = hwrng_buf_full(rb);
        hwrng_unlock();
        if (full) {
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
