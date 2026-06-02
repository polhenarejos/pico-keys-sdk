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

#ifndef _NEUG_H_
#define _NEUG_H_
#include <stdint.h>
#include <stddef.h>

void hwrng_init(uint8_t *buf, size_t size);
size_t hwrng_read(uint8_t *buf, size_t len);
void hwrng_flush(void);
void hwrng_wait_full(void);
void *hwrng_task(void);
uint32_t hwrng_get(void);

#endif
