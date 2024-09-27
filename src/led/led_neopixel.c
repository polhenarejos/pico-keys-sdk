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

#ifdef ESP_PLATFORM

#include "driver/gpio.h"
#include "neopixel.h"

tNeopixelContext neopixel = NULL;

tNeopixel pixel[] = {
    { 0, NP_RGB(0,  0,  0) }, /* off */
    { 0, NP_RGB(255,  0, 0) }, /* red */
    { 0, NP_RGB(0, 255,  0) }, /* green */
    { 0, NP_RGB(0, 0,  255) }, /* blue */
    { 0, NP_RGB(255,  255, 0) }, /* yellow */
    { 0, NP_RGB(255,  0, 255) }, /* magenta */
    { 0, NP_RGB(0, 255,  255) }, /* cyan */
    { 0, NP_RGB(255, 255,  255) }, /* white */
};

void led_driver_init() {
    uint8_t gpio = GPIO_NUM_48;
    if (file_has_data(ef_phy)) {
        if (file_read_uint8_offset(ef_phy, PHY_OPTS) & PHY_OPT_GPIO) {
            gpio = file_get_data(ef_phy)[PHY_LED_GPIO];
        }
    }
    neopixel = neopixel_Init(1, gpio);
}

void led_driver_color(uint8_t color, uint32_t led_brightness, float progress) {
    static tNeopixel spx = {.index = 0, .rgb = 0};
    if (!led_dimmable) {
        progress = progress >= 0.5 ? 1 : 0;
    }
    float brightness = ((float)led_brightness / MAX_BTNESS) * ((float)led_phy_btness / MAX_BTNESS) * progress;
    uint32_t pixel_color = pixel[color].rgb;
    uint8_t r = (pixel_color >> 16) & 0xFF;
    uint8_t g = (pixel_color >> 8) & 0xFF;
    uint8_t b = (pixel_color) & 0xFF;

    r = (uint8_t)(r * brightness);
    g = (uint8_t)(g * brightness);
    b = (uint8_t)(b * brightness);
    spx.rgb = NP_RGB(r, g, b);
    neopixel_SetPixel(neopixel, &spx, 1);
}

#endif
