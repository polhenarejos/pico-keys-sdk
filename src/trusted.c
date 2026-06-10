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

#include "trusted.h"

#include <stdlib.h>
#include <string.h>

#include "mbedtls/sha256.h"

extern void picokeys_trusted_set_allocators(void *(*calloc_impl)(size_t, size_t),
                                            void (*free_impl)(void *));
extern void picokeys_trusted_set_memops(picokeys_trusted_memset_fn memset_impl,
                                        picokeys_trusted_memcpy_fn memcpy_impl,
                                        picokeys_trusted_memmove_fn memmove_impl,
                                        picokeys_trusted_memcmp_fn memcmp_impl,
                                        picokeys_trusted_strlen_fn strlen_impl,
                                        picokeys_trusted_strncmp_fn strncmp_impl,
                                        picokeys_trusted_strncpy_fn strncpy_impl,
                                        picokeys_trusted_strchr_fn strchr_impl,
                                        picokeys_trusted_calloc_fn calloc_impl,
                                        picokeys_trusted_free_fn free_impl);

const uint8_t *trusted_region_start(void) {
    return __trusted_start;
}

const uint8_t *trusted_region_end(void) {
    return __trusted_end;
}

size_t trusted_region_size(void) {
    return (size_t)(__trusted_end - __trusted_start);
}

void trusted_region_init(void) {
    picokeys_trusted_set_memops(memset, memcpy, memmove, memcmp,
                                strlen, strncmp, strncpy,
                                strchr, calloc, free);
}

int trusted_region_sha256(uint8_t out[32]) {
    return mbedtls_sha256(__trusted_start, trusted_region_size(), out, 0);
}
