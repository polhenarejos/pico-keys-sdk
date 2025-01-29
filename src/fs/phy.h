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

#ifndef _PHY_H_
#define _PHY_H_

#define EF_PHY       0xE020

#define PHY_VIDPID      0x0
#define PHY_LED_GPIO    0x4
#define PHY_LED_BTNESS  0x5
#define PHY_OPTS        0x6
#define PHY_UP_BTN      0x8
#define PHY_USB_PRODUCT 0x9


#define PHY_OPT_WCID    0x1
#define PHY_OPT_DIMM    0x2
#define PHY_OPT_DISABLE_POWER_RESET 0x4
#define PHY_OPT_LED_STEADY 0x8

#include <stdint.h>
#include <stdbool.h>

typedef struct phy_data {
    union {
        struct {
            uint16_t vid;
            uint16_t pid;
        };
        uint8_t vidpid[4];
    };
    uint8_t led_gpio;
    uint8_t led_brightness;
    uint16_t opts;
    uint8_t up_btn;
    char usb_product[32];
    bool vidpid_present;
    bool led_gpio_present;
    bool led_brightness_present;
    bool up_btn_present;
    bool usb_product_present;
} phy_data_t;

#define PHY_MAX_SIZE    47

#ifndef ENABLE_EMULATION
extern int phy_serialize_data(const phy_data_t *phy, uint8_t *data, uint16_t *len);
extern int phy_unserialize_data(const uint8_t *data, uint16_t len, phy_data_t *phy);
extern int phy_init();
extern int phy_save();
extern int phy_load();
extern phy_data_t phy_data;
#endif

#endif // _PHY_H_
