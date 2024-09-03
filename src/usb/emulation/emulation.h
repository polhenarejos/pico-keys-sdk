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

#ifndef _EMULATION_H_
#define _EMULATION_H_

#include <stdint.h>
#include <string.h>
#ifdef _MSC_VER
#include <windows.h>
#else
#include <sys/time.h>
#endif
#include <stdbool.h>

#define USB_BUFFER_SIZE 2048
extern int emul_init(char *host, uint16_t port);
extern uint8_t emul_rx[USB_BUFFER_SIZE];
extern uint16_t emul_rx_size, emul_tx_size;
extern uint16_t driver_write_emul(uint8_t itf, const uint8_t *buffer, uint16_t buffer_size);
extern uint16_t emul_read(uint8_t itf);

static inline uint32_t board_millis() {
    struct timeval start;
    gettimeofday(&start, NULL);
    return start.tv_sec * 1000 + start.tv_usec / 1000;
}

#ifdef USB_ITF_HID
typedef uint8_t hid_report_type_t;
#endif

#ifdef USB_ITF_CCID
static inline uint32_t tud_vendor_n_available(uint8_t itf) {
    (void) itf;
    return emul_rx_size;
}
static inline uint32_t tud_vendor_n_read(uint8_t itf, uint8_t *buffer, uint32_t n) {
    (void) itf;
    if (n > emul_rx_size) {
        n = emul_rx_size;
    }
    memcpy(buffer, emul_rx, n);
    emul_rx_size = 0;
    return n;
}
extern void tud_vendor_tx_cb(uint8_t itf, uint32_t sent_bytes);
extern uint32_t tud_vendor_n_write(uint8_t itf, const uint8_t *buffer, uint32_t n);
static inline uint32_t tud_vendor_n_flush(uint8_t itf) {
    (void) itf;
    return emul_tx_size;
}
#endif

#ifdef USB_ITF_HID
extern void tud_hid_report_complete_cb(uint8_t instance, uint8_t const *report, uint16_t len);
extern bool tud_hid_n_report(uint8_t itf, uint8_t report_id, const uint8_t *buffer, uint32_t n);
#endif

#include <pthread.h>
#include <semaphore.h>
typedef struct {
    pthread_mutex_t mtx;
    pthread_cond_t  cnd;
    size_t        size_elem;
    size_t num_elem;
    size_t max_elem;
    uint8_t buf[1024];
    bool is_init;
} queue_t;

static inline void queue_free(queue_t *a) {
    pthread_mutex_destroy(&a->mtx);
    pthread_cond_destroy(&a->cnd);
    a->is_init = false;
}
static inline void queue_init(queue_t *a, size_t size_elem, size_t max_elem) {
    if (a->is_init) {
        queue_free(a);
    }
    pthread_mutex_init(&a->mtx, NULL);
    pthread_cond_init(&a->cnd, NULL);
    a->size_elem = size_elem;
    a->max_elem = max_elem;
    a->num_elem = 0;
    a->is_init = true;
}
static inline void queue_add_blocking(queue_t *a, const void *b) {
    pthread_mutex_lock(&a->mtx);
    while (a->num_elem == a->max_elem) {
        pthread_cond_wait(&a->cnd, &a->mtx);
    }
    memcpy(a->buf + a->num_elem * a->size_elem, b, a->size_elem);
    a->num_elem++;
    pthread_cond_signal(&a->cnd);
    pthread_mutex_unlock(&a->mtx);
}
static inline void queue_remove_blocking(queue_t *a, void *b) {
    pthread_mutex_lock(&a->mtx);
    while (a->num_elem == 0) {
        pthread_cond_wait(&a->cnd, &a->mtx);
    }
    memcpy(b, a->buf, a->size_elem);
    memmove(a->buf, a->buf + a->size_elem, a->size_elem * (a->num_elem - 1));
    a->num_elem--;
    pthread_cond_signal(&a->cnd);
    pthread_mutex_unlock(&a->mtx);
}
static inline int queue_try_add(queue_t *a, const void *b) {
    pthread_mutex_lock(&a->mtx);
    if (a->num_elem == a->max_elem) {
        pthread_mutex_unlock(&a->mtx);
        return 0;
    }
    memcpy(a->buf + a->num_elem * a->size_elem, b, a->size_elem);
    a->num_elem++;
    pthread_cond_signal(&a->cnd);
    pthread_mutex_unlock(&a->mtx);
    return 1;
}
static inline int queue_try_remove(queue_t *a, void *b) {
    pthread_mutex_lock(&a->mtx);
    if (a->num_elem == 0) {
        pthread_mutex_unlock(&a->mtx);
        return 0;
    }
    memcpy(b, a->buf, a->size_elem);
    memmove(a->buf, a->buf + a->size_elem, a->size_elem * (a->num_elem - 1));
    a->num_elem--;
    pthread_cond_signal(&a->cnd);
    pthread_mutex_unlock(&a->mtx);
    return 1;
}
static inline int queue_is_empty(queue_t *a) {
    pthread_mutex_lock(&a->mtx);
    bool ret = a->num_elem == 0;
    pthread_mutex_unlock(&a->mtx);
    return ret;
}
static inline int queue_is_full(queue_t *a) {
    pthread_mutex_lock(&a->mtx);
    bool ret = a->num_elem == a->max_elem;
    pthread_mutex_unlock(&a->mtx);
    return ret;
}
static inline void queue_clear(queue_t *a) {
    pthread_mutex_lock(&a->mtx);
    a->num_elem = 0;
    pthread_mutex_unlock(&a->mtx);
}
extern pthread_t hcore0, hcore1;
#define multicore_launch_core1(a) pthread_create(&hcore1, NULL, (void *(*) (void *))a, NULL)
#define multicore_reset_core1()

typedef pthread_mutex_t mutex_t;
typedef sem_t semaphore_t;
#define mutex_init(a) pthread_mutex_init(a, NULL)
#define mutex_try_enter(a,b) (pthread_mutex_trylock(a) == 0)
#define mutex_enter_blocking(a) pthread_mutex_lock(a)
#define mutex_exit(a) pthread_mutex_unlock(a)
#define sem_release(a) sem_post(a)
#define sem_acquire_blocking(a) sem_wait(a)
#define multicore_lockout_victim_init() (void)0

#endif // _EMULATION_H_
