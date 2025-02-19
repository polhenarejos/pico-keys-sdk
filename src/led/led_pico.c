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

#if defined(PICO_DEFAULT_LED_PIN) && !defined(PICO_DEFAULT_WS2812_PIN) && !defined(PIMORONI_TINY2040) && !defined(PIMORONI_TINY2350)

uint8_t gpio = PICO_DEFAULT_LED_PIN;

void led_driver_init() {
    if (phy_data.led_gpio_present) {
        gpio = phy_data.led_gpio;
    }
    gpio_init(gpio);
    gpio_set_dir(gpio, GPIO_OUT);
}

void led_driver_color(uint8_t color, uint32_t led_brightness, float progress) {
    (void)led_brightness;
    gpio_put(gpio, progress >= 0.5);
}

#endif
