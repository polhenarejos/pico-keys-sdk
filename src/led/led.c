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

#include <stdio.h>
#include <stdlib.h>
#include "pico_keys.h"
#ifdef PICO_PLATFORM
#include "bsp/board.h"
#elif defined(ESP_PLATFORM)
#include "driver/gpio.h"
#include "esp_compat.h"
#elif defined(ENABLE_EMULATION)
#include "emulation.h"
#endif

led_driver_t *led_driver = NULL;

static uint32_t led_mode = MODE_NOT_MOUNTED;

void led_set_mode(uint32_t mode) {
    led_mode = mode;
}

uint32_t led_get_mode() {
    return led_mode;
}

void led_blinking_task() {
#if defined(PICO_PLATFORM) || defined(ESP_PLATFORM)
    static uint32_t start_ms = 0;
    static uint32_t stop_ms = 0;
    static uint32_t last_led_update_ms = 0;
    static uint8_t led_state = false;
    uint8_t state = led_state;
#ifdef PICO_DEFAULT_LED_PIN_INVERTED
    state = !state;
#endif
    uint32_t led_brightness = (led_mode & LED_BTNESS_MASK) >> LED_BTNESS_SHIFT;
    uint32_t led_color = (led_mode & LED_COLOR_MASK) >> LED_COLOR_SHIFT;
    uint32_t led_off = (led_mode & LED_OFF_MASK) >> LED_OFF_SHIFT;
    uint32_t led_on = (led_mode & LED_ON_MASK) >> LED_ON_SHIFT;

    float progress = 0;

    if (stop_ms > start_ms) {
        progress = (float)(board_millis() - start_ms) / (stop_ms - start_ms);
    }

    if (!state) {
        progress = 1. - progress;
    }
    if (phy_data.opts & PHY_OPT_LED_STEADY) {
        progress = 1;
    }

    // limit the frequency of LED status updates
    if (board_millis() - last_led_update_ms > 2) {
        led_driver->set_color(led_color, led_brightness, progress);
        last_led_update_ms = board_millis();
    }

    if (board_millis() >= stop_ms){
        start_ms = stop_ms;
        led_state ^= 1; // toggle
        stop_ms = start_ms + (led_state ? led_on : led_off);
    }
#endif
}

void led_off_all() {
#if defined(PICO_PLATFORM) || defined(ESP_PLATFORM)
    led_driver->set_color(LED_COLOR_OFF, 0, 0);
#endif
}

extern led_driver_t led_driver_pico;
extern led_driver_t led_driver_cyw43;
extern led_driver_t led_driver_ws2812;
extern led_driver_t led_driver_neopixel;
extern led_driver_t led_driver_pimoroni;

void led_driver_init_dummy() {
    // Do nothing
}

void led_driver_color_dummy(uint8_t color, uint32_t led_brightness, float progress) {
    (void)color;
    (void)led_brightness;
    (void)progress;
    // Do nothing
}

led_driver_t led_driver_dummy = {
    .init = led_driver_init_dummy,
    .set_color = led_driver_color_dummy,
};

void led_init() {
    led_driver = &led_driver_dummy;
#if defined(PICO_PLATFORM) || defined(ESP_PLATFORM)
    // Guess default driver
#if defined(PIMORONI_TINY2040) || defined(PIMORONI_TINY2350)
    led_driver = &led_driver_pimoroni;
    phy_data.led_driver = phy_data.led_driver_present ? phy_data.led_driver : PHY_LED_DRIVER_PIMORONI;
#elif defined(CYW43_WL_GPIO_LED_PIN)
    led_driver = &led_driver_cyw43;
    phy_data.led_driver = phy_data.led_driver_present ? phy_data.led_driver : PHY_LED_DRIVER_CYW43;
    phy_data.led_gpio = phy_data.led_gpio_present ? phy_data.led_gpio : CYW43_WL_GPIO_LED_PIN;
#elif defined(PICO_DEFAULT_WS2812_PIN)
    led_driver = &led_driver_ws2812;
    phy_data.led_driver = phy_data.led_driver_present ? phy_data.led_driver : PHY_LED_DRIVER_WS2812;
    phy_data.led_gpio = phy_data.led_gpio_present ? phy_data.led_gpio : PICO_DEFAULT_WS2812_PIN;
#elif defined(ESP_PLATFORM)
    #if defined(CONFIG_IDF_TARGET_ESP32S3)
        #define NEOPIXEL_PIN GPIO_NUM_48
    #elif defined(CONFIG_IDF_TARGET_ESP32S2)
        #define NEOPIXEL_PIN GPIO_NUM_15
    #elif defined(CONFIG_IDF_TARGET_ESP32C6)
        #define NEOPIXEL_PIN GPIO_NUM_8
    #else
        #define NEOPIXEL_PIN GPIO_NUM_27
    #endif
    led_driver = &led_driver_neopixel;
    phy_data.led_driver = phy_data.led_driver_present ? phy_data.led_driver : PHY_LED_DRIVER_NEOPIXEL;
    phy_data.led_gpio = phy_data.led_gpio_present ? phy_data.led_gpio : NEOPIXEL_PIN;
#elif defined(PICO_DEFAULT_LED_PIN)
    led_driver = &led_driver_pico;
    phy_data.led_driver = phy_data.led_driver_present ? phy_data.led_driver : PHY_LED_DRIVER_PICO;
    phy_data.led_gpio = phy_data.led_gpio_present ? phy_data.led_gpio : PICO_DEFAULT_LED_PIN;
#endif
    if (phy_data.led_driver_present) {
        switch (phy_data.led_driver) {
#ifdef ESP_PLATFORM
            case PHY_LED_DRIVER_NEOPIXEL:
                led_driver = &led_driver_neopixel;
                break;
#else
            case PHY_LED_DRIVER_PICO:
                led_driver = &led_driver_pico;
                break;
#ifdef CYW43_WL_GPIO_LED_PIN
            case PHY_LED_DRIVER_CYW43:
                led_driver = &led_driver_cyw43;
                break;
#endif
            case PHY_LED_DRIVER_WS2812:
                led_driver = &led_driver_ws2812;
                break;
            case PHY_LED_DRIVER_PIMORONI:
                led_driver = &led_driver_pimoroni;
                break;
#endif
            default:
                break;
        }
    }
    phy_data.led_driver_present = true;
    phy_data.led_gpio_present = true;
    led_driver->init();
    led_set_mode(MODE_NOT_MOUNTED);
#endif
}
