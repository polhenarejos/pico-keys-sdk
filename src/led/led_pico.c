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

#ifdef PICO_DEFAULT_LED_PIN
uint8_t gpio = PICO_DEFAULT_LED_PIN;
#else
uint8_t gpio = 0;
#endif

#ifdef PICO_PLATFORM
void led_driver_init_pico() {
    if (phy_data.led_gpio_present) {
        gpio = phy_data.led_gpio;
    }
    gpio_init(gpio);
    gpio_set_dir(gpio, GPIO_OUT);
}

void led_driver_color_pico(uint8_t color, uint32_t led_brightness, float progress) {
    (void)led_brightness;
    gpio_put(gpio, progress >= 0.5);
}

led_driver_t led_driver_pico = {
    .init = led_driver_init_pico,
    .set_color = led_driver_color_pico,
};

#endif
