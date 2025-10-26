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


 #ifdef _MSC_VER
#ifndef _PTHREAD_H_
#define _PTHREAD_H_
#include <windows.h>
#include <stdint.h>

typedef HANDLE pthread_t;
typedef CRITICAL_SECTION pthread_mutex_t;

typedef struct {
    CONDITION_VARIABLE cond;
} pthread_cond_t;

// Mutex
static inline int pthread_mutex_init(pthread_mutex_t *m, void *a) {
    (void)a;
    InitializeCriticalSection(m);
    return 0;
}

static inline int pthread_mutex_lock(pthread_mutex_t *m) {
    EnterCriticalSection(m);
    return 0;
}

static inline int pthread_mutex_unlock(pthread_mutex_t *m) {
    LeaveCriticalSection(m);
    return 0;
}

static inline int pthread_mutex_destroy(pthread_mutex_t *m) {
    DeleteCriticalSection(m);
    return 0;
}

// Thread
static DWORD WINAPI thread_entry(LPVOID param) {
    void **args = (void **)param;
    void *(*fn)(void *) = (void *(*)(void *))(uintptr_t)args[0];
    void *arg = args[1];
    fn(arg);
    free(param);
    return 0;
}

static inline int pthread_create(pthread_t *t, void *a, void *(*fn)(void *), void *arg) {
    (void)a;
    void **params = malloc(2 * sizeof(void *));
    if (!params) return -1;
    params[0] = (void *)(uintptr_t)fn;
    params[1] = arg;
    *t = CreateThread(NULL, 0, thread_entry, params, 0, NULL);
    return *t ? 0 : -1;
}

static inline int pthread_join(pthread_t t, void **ret) {
    WaitForSingleObject(t, INFINITE);
    CloseHandle(t);
    if (ret) *ret = NULL;
    return 0;
}

// Condition variable
static inline int pthread_cond_init(pthread_cond_t *c, void *a) {
    (void)a;
    InitializeConditionVariable(&c->cond);
    return 0;
}

static inline int pthread_cond_destroy(pthread_cond_t *c) {
    (void)c;
    return 0;
}

static inline int pthread_cond_wait(pthread_cond_t *c, pthread_mutex_t *m) {
    SleepConditionVariableCS(&c->cond, m, INFINITE);
    return 0;
}

static inline int pthread_cond_signal(pthread_cond_t *c) {
    WakeConditionVariable(&c->cond);
    return 0;
}

static inline int pthread_cond_broadcast(pthread_cond_t *c) {
    WakeAllConditionVariable(&c->cond);
    return 0;
}

static inline int pthread_mutex_trylock(pthread_mutex_t *m){
    return TryEnterCriticalSection(m) ? 0 : EBUSY;
}

#endif // _PTHREAD_H_
#endif // _MSC_VER
