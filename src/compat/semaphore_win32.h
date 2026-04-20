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
#ifndef _SEMAPHORE_H_
#define _SEMAPHORE_H_

#include <windows.h>

typedef struct {
    HANDLE handle;
} sem_t;

static inline int sem_init(sem_t *sem, int pshared, unsigned int value) {
    (void)pshared;
    sem->handle = CreateSemaphore(NULL, value, 0x7FFFFFFF, NULL);
    return sem->handle ? 0 : -1;
}

static inline int sem_wait(sem_t *sem) {
    return WaitForSingleObject(sem->handle, INFINITE) == WAIT_OBJECT_0 ? 0 : -1;
}

static inline int sem_post(sem_t *sem) {
    return ReleaseSemaphore(sem->handle, 1, NULL) ? 0 : -1;
}

static inline int sem_destroy(sem_t *sem) {
    return CloseHandle(sem->handle) ? 0 : -1;
}

#endif // _SEMAPHORE_H_
#endif // _MSC_VER
