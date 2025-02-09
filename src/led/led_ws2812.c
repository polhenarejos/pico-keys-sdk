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

#ifdef PICO_DEFAULT_WS2812_PIN

#include "hardware/pio.h"
#include "hardware/clocks.h"

#define ws2812_wrap_target 0
#define ws2812_wrap 3
#define ws2812_pio_version 0

#define ws2812_T1 3
#define ws2812_T2 3
#define ws2812_T3 4

static const uint16_t ws2812_program_instructions[] = {
            //     .wrap_target
    0x6321, //  0: out    x, 1            side 0 [3]
    0x1223, //  1: jmp    !x, 3           side 1 [2]
    0x1200, //  2: jmp    0               side 1 [2]
    0xa242, //  3: nop                    side 0 [2]
            //     .wrap
};

static const struct pio_program ws2812_program = {
    .instructions = ws2812_program_instructions,
    .length = 4,
    .origin = -1,
    .pio_version = ws2812_pio_version,
#if PICO_PIO_VERSION > 0
    .used_gpio_ranges = 0x0
#endif
};

static inline pio_sm_config ws2812_program_get_default_config(uint offset) {
    pio_sm_config c = pio_get_default_sm_config();
    sm_config_set_wrap(&c, offset + ws2812_wrap_target, offset + ws2812_wrap);
    sm_config_set_sideset(&c, 1, false, false);
    return c;
}

static inline void ws2812_program_init(PIO pio, uint sm, uint offset, uint pin, float freq, bool rgbw) {
    pio_gpio_init(pio, pin);
    pio_sm_set_consecutive_pindirs(pio, sm, pin, 1, true);
    pio_sm_config c = ws2812_program_get_default_config(offset);
    sm_config_set_sideset_pins(&c, pin);
    sm_config_set_out_shift(&c, false, true, rgbw ? 32 : 24);
    sm_config_set_fifo_join(&c, PIO_FIFO_JOIN_TX);
    int cycles_per_bit = ws2812_T1 + ws2812_T2 + ws2812_T3;
    float div = clock_get_hz(clk_sys) / (freq * cycles_per_bit);
    sm_config_set_clkdiv(&c, div);
    pio_sm_init(pio, sm, offset, &c);
    pio_sm_set_enabled(pio, sm, true);
}

void led_driver_init() {
    PIO pio = pio0;
    int sm = 0;
    uint offset = pio_add_program(pio, &ws2812_program);
    uint8_t gpio = PICO_DEFAULT_WS2812_PIN;
    if (phy_data.led_gpio_present) {
        gpio = phy_data.led_gpio;
    }
    ws2812_program_init(pio, sm, offset, gpio, 800000, false);
}

struct urgb_color {
    uint8_t r;
    uint8_t g;
    uint8_t b;
};

static struct urgb_color urgb_color_table[] = {
    {0x00, 0x00, 0x00}, // 0: off       LED_COLOR_OFF
    {0xff, 0x00, 0x00}, // 1: red       LED_COLOR_RED
    {0x00, 0xff, 0x00}, // 2: green     LED_COLOR_GREEN
    {0x00, 0x00, 0xff}, // 3: blue      LED_COLOR_BLUE
    {0xff, 0xff, 0x00}, // 4: yellow    LED_COLOR_YELLOW
    {0xff, 0x00, 0xff}, // 5: magenta   LED_COLOR_MAGENTA
    {0x00, 0xff, 0xff}, // 6: cyan      LED_COLOR_CYAN
    {0xff, 0xff, 0xff}  // 7: white     LED_COLOR_WHITE
};

static inline uint32_t urgb_u32(uint8_t r, uint8_t g, uint8_t b) {
    return ((uint32_t) (r) << 8) |  // For GRB data ordering WS2812
           ((uint32_t) (g) << 16) |
           (uint32_t) (b);
#if 0   // TODO: How to adapt WS2812 with different data ordering ?
    return ((uint32_t)(r) << 16) |  // For RGB data ordering WS2812
           ((uint32_t)(g) << 8) |
           (uint32_t)(b);
#endif
}

static inline void ws2812_put_pixel(uint32_t u32_pixel) {
    pio_sm_put_blocking(pio0, 0, u32_pixel << 8u);
}

void led_driver_color(uint8_t color, uint32_t led_brightness, float progress) {
    if (!(phy_data.opts & PHY_OPT_DIMM)) {
        progress = progress >= 0.5 ? 1 : 0;
    }
    uint32_t led_phy_btness = phy_data.led_brightness_present ? phy_data.led_brightness : MAX_BTNESS;

    float brightness = ((float)led_brightness / MAX_BTNESS) * ((float)led_phy_btness / MAX_BTNESS) * progress;
    struct urgb_color pixel_color = urgb_color_table[color];
    pixel_color.r = (uint8_t)(pixel_color.r * brightness);
    pixel_color.g = (uint8_t)(pixel_color.g * brightness);
    pixel_color.b = (uint8_t)(pixel_color.b * brightness);

    ws2812_put_pixel(urgb_u32(pixel_color.r, pixel_color.g, pixel_color.b));
}

#endif
