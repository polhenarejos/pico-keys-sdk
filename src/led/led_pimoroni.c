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

#include "pico_keys.h"

#if defined(PIMORONI_TINY2040) || defined(PIMORONI_TINY2350)

#ifdef PIMORONI_TINY2040
#define LED_R_PIN TINY2040_LED_R_PIN
#define LED_G_PIN TINY2040_LED_G_PIN
#define LED_B_PIN TINY2040_LED_B_PIN
#elif defined(PIMORONI_TINY2350)
#define LED_R_PIN TINY2350_LED_R_PIN
#define LED_G_PIN TINY2350_LED_G_PIN
#define LED_B_PIN TINY2350_LED_B_PIN
#endif

uint8_t pixel[][3] = {
    {1, 1, 1}, // 0: off
    {0, 1, 1}, // 1: red
    {1, 0, 1}, // 2: green
    {1, 1, 0}, // 3: blue
    {0, 0, 1}, // 4: yellow
    {0, 1, 0}, // 5: magenta
    {1, 0, 0}, // 6: cyan
    {0, 0, 0}  // 7: white
};

void led_driver_init() {
    gpio_init(LED_R_PIN);
    gpio_set_dir(LED_R_PIN, GPIO_OUT);
    gpio_init(LED_G_PIN);
    gpio_set_dir(LED_G_PIN, GPIO_OUT);
    gpio_init(LED_B_PIN);
    gpio_set_dir(LED_B_PIN, GPIO_OUT);
}

void led_driver_color(uint8_t color, uint32_t led_brightness, float progress) {
    if (progress < 0.5) {
        color = LED_COLOR_OFF;
    }
    gpio_put(LED_R_PIN, pixel[color][0]);
    gpio_put(LED_G_PIN, pixel[color][1]);
    gpio_put(LED_B_PIN, pixel[color][2]);
}

#endif
