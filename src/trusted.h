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

#ifndef TRUSTED_FIRMWARE_H
#define TRUSTED_FIRMWARE_H

#include <stddef.h>
#include <stdint.h>

extern const uint8_t __trusted_start[];
extern const uint8_t __trusted_end[];
extern const uint8_t __trusted_load_start[];
extern const uint8_t __trusted_load_end[];

/* The canonical trusted measurement is always the flash image range. */
const uint8_t *trusted_region_start(void);
const uint8_t *trusted_region_end(void);
const uint8_t *trusted_region_load_start(void);
const uint8_t *trusted_region_load_end(void);
size_t trusted_region_size(void);
void trusted_region_init(void);
int trusted_region_sha256(uint8_t out[32]);

#endif
