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
#include "file.h"

#ifndef ENABLE_EMULATION

phy_data_t phy_data;

int phy_serialize_data(const phy_data_t *phy, uint8_t *data, uint16_t *len) {
    if (!phy || !data || !len) {
        return PICOKEY_ERR_NULL_PARAM;
    }
    uint8_t *p = data;
    if (phy->vidpid_present) {
        *p++ = PHY_VIDPID;
        *p++ = phy->vidpid[1];
        *p++ = phy->vidpid[0];
        *p++ = phy->vidpid[3];
        *p++ = phy->vidpid[2];
    }
    if (phy->led_gpio_present) {
        *p++ = PHY_LED_GPIO;
        *p++ = phy->led_gpio;
    }
    if (phy->led_brightness_present) {
        *p++ = PHY_LED_BTNESS;
        *p++ = phy->led_brightness;
    }
    *p++ = PHY_OPTS;
    p += put_uint16_t_be(phy->opts, p);
    if (phy->up_btn_present) {
        *p++ = PHY_UP_BTN;
        *p++ = phy->up_btn;
    }
    if (phy->usb_product_present) {
        *p++ = PHY_USB_PRODUCT;
        strcpy((char *)p, phy->usb_product);
        p += strlen(phy->usb_product);
        *p++ = '\0';
    }

    *len = p - data;
    return PICOKEY_OK;
}

int phy_unserialize_data(const uint8_t *data, uint16_t len, phy_data_t *phy) {
    if (!phy || !data || !len) {
        return PICOKEY_ERR_NULL_PARAM;
    }
    const uint8_t *p = data;
    while (p < data + len) {
        switch (*p++) {
            case PHY_VIDPID:
                memcpy(phy->vidpid, p, 4);
                phy->vidpid[1] = *p++;
                phy->vidpid[0] = *p++;
                phy->vidpid[3] = *p++;
                phy->vidpid[2] = *p++;
                phy->vidpid_present = true;
                break;
            case PHY_LED_GPIO:
                phy->led_gpio = *p++;
                phy->led_gpio_present = true;
                break;
            case PHY_LED_BTNESS:
                phy->led_brightness = *p++;
                phy->led_brightness_present = true;
                break;
            case PHY_OPTS:
                phy->opts = get_uint16_t_be(p);
                p += 2;
                break;
            case PHY_UP_BTN:
                phy->up_btn = *p++;
                phy->up_btn_present = true;
                break;
            case PHY_USB_PRODUCT:
                memset(phy->usb_product, 0, sizeof(phy->usb_product));
                strlcpy(phy->usb_product, (const char *)p, sizeof(phy->usb_product));
                phy->usb_product_present = true;
                p += strlen(phy->usb_product) + 1;
                break;
        }
    }
    return PICOKEY_OK;
}

int phy_init() {
    memset(&phy_data, 0, sizeof(phy_data_t));
    return phy_load();
}

int phy_save() {
    uint8_t tmp[PHY_MAX_SIZE] = {0};
    uint16_t tmp_len = 0;
    int ret = phy_serialize_data(&phy_data, tmp, &tmp_len);
    if (ret != PICOKEY_OK) {
        return ret;
    }
    file_put_data(ef_phy, tmp, tmp_len);
    low_flash_available();
    return PICOKEY_OK;
}

int phy_load() {
    if (file_has_data(ef_phy)) {
        return phy_unserialize_data(file_get_data(ef_phy), file_get_size(ef_phy), &phy_data);
    }
    return PICOKEY_OK;
}
#endif
