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

#include "mbedtls/sha256.h"

const uint8_t *trusted_region_start(void) {
    return __trusted_start;
}

const uint8_t *trusted_region_end(void) {
    return __trusted_end;
}

const uint8_t *trusted_region_load_start(void) {
    return __trusted_start;
}

const uint8_t *trusted_region_load_end(void) {
    return __trusted_end;
}

size_t trusted_region_size(void) {
    return (size_t)(__trusted_end - __trusted_start);
}

void trusted_region_init(void) {
    /* The trusted measurement is always taken from its flash image range. */
}

int trusted_region_sha256(uint8_t out[32]) {
    return mbedtls_sha256(__trusted_start, trusted_region_size(), out, 0);
}
