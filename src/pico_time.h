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

#ifndef TIME_H
#define TIME_H

#if defined(PICO_PLATFORM)
#include "pico/aon_timer.h"
#include "bsp/board.h"
#elif defined(ESP_PLATFORM)
#include "compat/esp_compat.h"
#include <time.h>
#else
#include <sys/time.h>
#include <time.h>
#include "compat/board.h"
#endif

extern bool has_set_rtc(void);
extern time_t get_rtc_time(void);
extern void set_rtc_time(time_t tv_sec);
extern void init_rtc(void);

#endif // TIME_H
