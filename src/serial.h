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

#ifndef _SERIAL_H_
#define _SERIAL_H_

#include <stdint.h>

#if !defined (PICO_PLATFORM)
#if __APPLE__
#define PICO_UNIQUE_BOARD_ID_SIZE_BYTES 16
#else
#define PICO_UNIQUE_BOARD_ID_SIZE_BYTES 8
#endif
typedef struct { uint8_t id[PICO_UNIQUE_BOARD_ID_SIZE_BYTES]; } picokey_serial_t;
#else
#include "pico/unique_id.h"
typedef pico_unique_board_id_t picokey_serial_t;
#endif

extern picokey_serial_t pico_serial;
extern char pico_serial_str[2 * PICO_UNIQUE_BOARD_ID_SIZE_BYTES + 1];
extern uint8_t pico_serial_hash[32];
extern void serial_init(void);

#endif //_SERIAL_H_
