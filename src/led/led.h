/*
 * This file is part of the Pico Keys SDK distribution (https://github.com/polhenarejos/pico-keys-sdk).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _LED_H_
#define _LED_H_

#include <stdint.h>

enum {
    LED_COLOR_OFF = 0,
    LED_COLOR_RED,
    LED_COLOR_GREEN,
    LED_COLOR_BLUE,
    LED_COLOR_YELLOW,
    LED_COLOR_MAGENTA,
    LED_COLOR_CYAN,
    LED_COLOR_WHITE
};

#define LED_OFF_BITS        14
#define LED_OFF_SHIFT       0
#define LED_OFF_MASK        (((1 << LED_OFF_BITS) - 1) << LED_OFF_SHIFT)
#define LED_ON_BITS         14
#define LED_ON_SHIFT        LED_OFF_BITS
#define LED_ON_MASK         (((1 << LED_ON_BITS) - 1) << LED_ON_SHIFT)
#define LED_COLOR_BITS      3
#define LED_COLOR_SHIFT     (LED_ON_BITS + LED_OFF_BITS)
#define LED_COLOR_MASK      (((1 << LED_COLOR_BITS) - 1) << LED_COLOR_SHIFT)

enum  {
    BLINK_NOT_MOUNTED = (LED_COLOR_RED << LED_COLOR_SHIFT) | (250 << LED_ON_SHIFT) | (250 << LED_OFF_SHIFT),
    BLINK_MOUNTED     = (LED_COLOR_GREEN << LED_COLOR_SHIFT) | (250 << LED_ON_SHIFT) | (250 << LED_OFF_SHIFT),
    BLINK_SUSPENDED   = (LED_COLOR_BLUE << LED_COLOR_SHIFT) | (500 << LED_ON_SHIFT) | (1000 << LED_OFF_SHIFT),
    BLINK_PROCESSING  = (LED_COLOR_GREEN << LED_COLOR_SHIFT) | (50 << LED_ON_SHIFT) | (50 << LED_OFF_SHIFT),
    BLINK_BUTTON      = (LED_COLOR_YELLOW << LED_COLOR_SHIFT) | (1000 << LED_ON_SHIFT) | (100 << LED_OFF_SHIFT),

    BLINK_ALWAYS_ON   = UINT32_MAX,
    BLINK_ALWAYS_OFF  = 0
};

extern void led_set_blink(uint32_t mode);
extern void led_blinking_task();
extern void led_off_all();
extern void led_init();

#endif // _LED_H_
