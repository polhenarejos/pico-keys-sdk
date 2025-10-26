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

#if defined(CONFIG_IDF_TARGET_ESP32S3)
    #define NEOPIXEL_PIN GPIO_NUM_48
#elif defined(CONFIG_IDF_TARGET_ESP32S2)
    #define NEOPIXEL_PIN GPIO_NUM_15
#elif defined(CONFIG_IDF_TARGET_ESP32C6)
    #define NEOPIXEL_PIN GPIO_NUM_8
#else
    #define NEOPIXEL_PIN GPIO_NUM_27
#endif

void led_driver_init_neopixel() {
    uint8_t gpio = NEOPIXEL_PIN;
    if (phy_data.led_gpio_present) {
        gpio = phy_data.led_gpio;
    }
    neopixel = neopixel_Init(1, gpio);
}

void led_driver_color_neopixel(uint8_t color, uint32_t led_brightness, float progress) {
    static tNeopixel spx = {.index = 0, .rgb = 0};
    if (!(phy_data.opts & PHY_OPT_DIMM)) {
        progress = progress >= 0.5 ? 1 : 0;
    }
    uint32_t led_phy_btness = phy_data.led_brightness_present ? phy_data.led_brightness : MAX_BTNESS;
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

led_driver_t led_driver_neopixel = {
    .init = led_driver_init_neopixel,
    .set_color = led_driver_color_neopixel,
};

#endif
