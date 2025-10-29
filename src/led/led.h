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

#define LED_OFF_BITS        12
#define LED_OFF_SHIFT       0
#define LED_OFF_MASK        (((1 << LED_OFF_BITS) - 1) << LED_OFF_SHIFT)
#define LED_ON_BITS         12
#define LED_ON_SHIFT        LED_OFF_BITS
#define LED_ON_MASK         (((1 << LED_ON_BITS) - 1) << LED_ON_SHIFT)
#define LED_COLOR_BITS      3
#define LED_COLOR_SHIFT     (LED_ON_BITS + LED_OFF_BITS)
#define LED_COLOR_MASK      (((1 << LED_COLOR_BITS) - 1) << LED_COLOR_SHIFT)
#define LED_BTNESS_BITS     4
#define LED_BTNESS_SHIFT    (LED_ON_BITS + LED_OFF_BITS + LED_COLOR_BITS)
#define LED_BTNESS_MASK     (((1 << LED_BTNESS_BITS) - 1 ) << LED_BTNESS_SHIFT)

#define MAX_BTNESS          ((1 << LED_BTNESS_BITS) - 1)
#define HALF_BTNESS         ((1 << (LED_BTNESS_BITS - 1)) - 1)

// steady on
#define LED_ON_NO_BLINK     ((1000 << LED_ON_SHIFT) | (0 << LED_OFF_SHIFT))

#if defined(PICO_DEFAULT_LED_PIN) && !defined(PICO_DEFAULT_WS2812_PIN) && !defined(PIMORONI_TINY2040) && !defined(PIMORONI_TINY2350)
// boards with plain old monochrome LED
enum  {
    MODE_NOT_MOUNTED = (MAX_BTNESS << LED_BTNESS_SHIFT) | (LED_COLOR_WHITE << LED_COLOR_SHIFT) | (500 << LED_ON_SHIFT) | (500 << LED_OFF_SHIFT),
    MODE_MOUNTED     = 0, // no distraction when idle
    MODE_SUSPENDED   = 0, // no distraction when idle
    MODE_PROCESSING  = (MAX_BTNESS << LED_BTNESS_SHIFT) | (LED_COLOR_WHITE << LED_COLOR_SHIFT) | (50 << LED_ON_SHIFT)  | (50 << LED_OFF_SHIFT),
    MODE_BUTTON      = (MAX_BTNESS << LED_BTNESS_SHIFT) | (LED_COLOR_WHITE << LED_COLOR_SHIFT) | (250 << LED_ON_SHIFT) | (250 << LED_OFF_SHIFT),
    MODE_ALWAYS_ON   = UINT32_MAX,
    MODE_ALWAYS_OFF  = 0
};
#else
// boards with Neopixel or something similar
enum  {
    MODE_NOT_MOUNTED = (MAX_BTNESS << LED_BTNESS_SHIFT) | (LED_COLOR_RED << LED_COLOR_SHIFT) | (500 << LED_ON_SHIFT) | (500 << LED_OFF_SHIFT),
    MODE_MOUNTED     = (MAX_BTNESS << LED_BTNESS_SHIFT) | (LED_COLOR_GREEN << LED_COLOR_SHIFT) | (500 << LED_ON_SHIFT) | (500 << LED_OFF_SHIFT),
    MODE_SUSPENDED   = (MAX_BTNESS << LED_BTNESS_SHIFT) | (LED_COLOR_BLUE << LED_COLOR_SHIFT) | (1000 << LED_ON_SHIFT) | (2000 << LED_OFF_SHIFT),
    MODE_PROCESSING  = (MAX_BTNESS << LED_BTNESS_SHIFT) | (LED_COLOR_GREEN << LED_COLOR_SHIFT) | (50 << LED_ON_SHIFT) | (50 << LED_OFF_SHIFT),
    MODE_BUTTON      = (MAX_BTNESS << LED_BTNESS_SHIFT) | (LED_COLOR_YELLOW << LED_COLOR_SHIFT) | (1000 << LED_ON_SHIFT) | (100 << LED_OFF_SHIFT),

    MODE_ALWAYS_ON   = UINT32_MAX,
    MODE_ALWAYS_OFF  = 0
};
#endif

extern void led_set_mode(uint32_t mode);
extern uint32_t led_get_mode();
extern void led_blinking_task();
extern void led_off_all();
extern void led_init();

typedef struct {
    void (*init)();
    void (*set_color)(uint8_t color, uint32_t led_brightness, float progress);
} led_driver_t;

extern led_driver_t *led_driver;

#endif // _LED_H_
