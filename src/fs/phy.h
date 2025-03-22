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
#define PHY_ENABLED_CURVES 0xA
#define PHY_ENABLED_USB_ITF 0xB

#define PHY_OPT_WCID    0x1
#define PHY_OPT_DIMM    0x2
#define PHY_OPT_DISABLE_POWER_RESET 0x4
#define PHY_OPT_LED_STEADY 0x8

#define PHY_CURVE_SECP256R1  0x1
#define PHY_CURVE_SECP384R1  0x2
#define PHY_CURVE_SECP521R1  0x4
#define PHY_CURVE_SECP256K1 0x8
#define PHY_CURVE_BP256R1 0x10
#define PHY_CURVE_BP384R1 0x20
#define PHY_CURVE_BP512R1 0x40
#define PHY_CURVE_ED25519 0x80
#define PHY_CURVE_ED448 0x100
#define PHY_CURVE_CURVE25519 0x200
#define PHY_CURVE_CURVE448 0x400

#define PHY_USB_ITF_CCID 0x1
#define PHY_USB_ITF_WCID 0x2
#define PHY_USB_ITF_HID 0x4
#define PHY_USB_ITF_KB 0x8

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

    uint32_t enabled_curves;

    char usb_product[32];

    uint16_t opts;

    uint8_t led_gpio;
    uint8_t led_brightness;
    uint8_t up_btn;
    uint8_t enabled_usb_itf;

    bool vidpid_present;
    bool led_gpio_present;
    bool led_brightness_present;
    bool up_btn_present;
    bool usb_product_present;
    bool enabled_curves_present;
    bool enabled_usb_itf_present;

} phy_data_t;

#define PHY_MAX_SIZE    ((2+4)+(2+4)+(2+32)+(2+2)+(2+1)+(2+1)+(2+1)+(2+1))

#ifndef ENABLE_EMULATION
extern int phy_serialize_data(const phy_data_t *phy, uint8_t *data, uint16_t *len);
extern int phy_unserialize_data(const uint8_t *data, uint16_t len, phy_data_t *phy);
extern int phy_init();
extern int phy_save();
extern int phy_load();
extern phy_data_t phy_data;
#endif

#endif // _PHY_H_
