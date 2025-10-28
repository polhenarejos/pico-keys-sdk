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

#ifndef QUEUE_H
#define QUEUE_H

#ifdef _MSC_VER
#include "pthread_win32.h"
#include "semaphore_win32.h"
#else
#include <pthread.h>
#include <semaphore.h>
#endif
#include <stdbool.h>
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
#define multicore_launch_func_core1(a) pthread_create(&hcore1, NULL, (void *(*) (void *))a, NULL)
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

#endif // QUEUE_H
