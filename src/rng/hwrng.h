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

#define NEUG_PRE_LOOP 32

#include <stdlib.h>
#if defined(PICO_PLATFORM)
#include "pico/stdlib.h"
#endif

void neug_init(uint32_t *buf, uint8_t size);
uint32_t neug_get();
void neug_flush(void);
void neug_wait_full();

#endif
