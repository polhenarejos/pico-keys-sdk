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

#include "mbedtls/platform_util.h"
#include "trusted.h"

#include <stddef.h>

static picokeys_trusted_memset_fn picokeys_trusted_memset_impl;
static picokeys_trusted_memcpy_fn picokeys_trusted_memcpy_impl;
static picokeys_trusted_memmove_fn picokeys_trusted_memmove_impl;
static picokeys_trusted_memcmp_fn picokeys_trusted_memcmp_impl;
static picokeys_trusted_strlen_fn picokeys_trusted_strlen_impl;
static picokeys_trusted_strncmp_fn picokeys_trusted_strncmp_impl;
static picokeys_trusted_strncpy_fn picokeys_trusted_strncpy_impl;
static picokeys_trusted_strchr_fn picokeys_trusted_strchr_impl;
static picokeys_trusted_calloc_fn picokeys_trusted_calloc_impl;
static picokeys_trusted_free_fn picokeys_trusted_free_impl;

static void picokeys_trusted_uninitialized_call(void)
{
    __builtin_trap();
}

void picokeys_trusted_set_memops(picokeys_trusted_memset_fn memset_impl,
                                 picokeys_trusted_memcpy_fn memcpy_impl,
                                 picokeys_trusted_memmove_fn memmove_impl,
                                 picokeys_trusted_memcmp_fn memcmp_impl,
                                 picokeys_trusted_strlen_fn strlen_impl,
                                 picokeys_trusted_strncmp_fn strncmp_impl,
                                 picokeys_trusted_strncpy_fn strncpy_impl,
                                 picokeys_trusted_strchr_fn strchr_impl,
                                 picokeys_trusted_calloc_fn calloc_impl,
                                 picokeys_trusted_free_fn free_impl)
{
    picokeys_trusted_memset_impl = memset_impl;
    picokeys_trusted_memcpy_impl = memcpy_impl;
    picokeys_trusted_memmove_impl = memmove_impl;
    picokeys_trusted_memcmp_impl = memcmp_impl;
    picokeys_trusted_strlen_impl = strlen_impl;
    picokeys_trusted_strncmp_impl = strncmp_impl;
    picokeys_trusted_strncpy_impl = strncpy_impl;
    picokeys_trusted_strchr_impl = strchr_impl;
    picokeys_trusted_calloc_impl = calloc_impl;
    picokeys_trusted_free_impl = free_impl;
}

void *picokeys_trusted_memset(void *dst, int value, size_t len)
{
    if (picokeys_trusted_memset_impl == NULL) {
        picokeys_trusted_uninitialized_call();
    }
    return picokeys_trusted_memset_impl(dst, value, len);
}

void *picokeys_trusted_memcpy(void *dst, const void *src, size_t len)
{
    if (picokeys_trusted_memcpy_impl == NULL) {
        picokeys_trusted_uninitialized_call();
    }
    return picokeys_trusted_memcpy_impl(dst, src, len);
}

void *picokeys_trusted_memmove(void *dst, const void *src, size_t len)
{
    if (picokeys_trusted_memmove_impl == NULL) {
        picokeys_trusted_uninitialized_call();
    }
    return picokeys_trusted_memmove_impl(dst, src, len);
}

int picokeys_trusted_memcmp(const void *lhs, const void *rhs, size_t len)
{
    if (picokeys_trusted_memcmp_impl == NULL) {
        picokeys_trusted_uninitialized_call();
    }
    return picokeys_trusted_memcmp_impl(lhs, rhs, len);
}

size_t picokeys_trusted_strlen(const char *s)
{
    if (picokeys_trusted_strlen_impl == NULL) {
        picokeys_trusted_uninitialized_call();
    }
    return picokeys_trusted_strlen_impl(s);
}

int picokeys_trusted_strncmp(const char *lhs, const char *rhs, size_t len)
{
    if (picokeys_trusted_strncmp_impl == NULL) {
        picokeys_trusted_uninitialized_call();
    }
    return picokeys_trusted_strncmp_impl(lhs, rhs, len);
}

char *picokeys_trusted_strncpy(char *dst, const char *src, size_t len)
{
    if (picokeys_trusted_strncpy_impl == NULL) {
        picokeys_trusted_uninitialized_call();
    }
    return picokeys_trusted_strncpy_impl(dst, src, len);
}

char *picokeys_trusted_strchr(const char *s, int c)
{
    if (picokeys_trusted_strchr_impl == NULL) {
        picokeys_trusted_uninitialized_call();
    }
    return picokeys_trusted_strchr_impl(s, c);
}

void *picokeys_trusted_calloc(size_t nmemb, size_t size)
{
    if (picokeys_trusted_calloc_impl == NULL) {
        return NULL;
    }
    return picokeys_trusted_calloc_impl(nmemb, size);
}

void picokeys_trusted_free(void *ptr)
{
    if (picokeys_trusted_free_impl != NULL) {
        picokeys_trusted_free_impl(ptr);
    }
}

void mbedtls_platform_zeroize(void *buf, size_t len)
{
    if (buf != NULL && len != 0) {
        picokeys_trusted_memset(buf, 0, len);
        __asm__ volatile ("" ::: "memory");
    }
}
