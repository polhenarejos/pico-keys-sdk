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
#include "file.h"
#include "otp.h"

#ifndef ENABLE_EMULATION

phy_data_t phy_data;

int phy_serialize_data(const phy_data_t *phy, uint8_t *data, uint16_t *len) {
    if (!phy || !data || !len) {
        return PICOKEY_ERR_NULL_PARAM;
    }
    uint8_t *p = data;
    if (phy->vidpid_present) {
        *p++ = PHY_VIDPID;
        *p++ = 4;
        *p++ = phy->vidpid[1];
        *p++ = phy->vidpid[0];
        *p++ = phy->vidpid[3];
        *p++ = phy->vidpid[2];
    }
    if (phy->led_gpio_present) {
        *p++ = PHY_LED_GPIO;
        *p++ = 1;
        *p++ = phy->led_gpio;
    }
    if (phy->led_brightness_present) {
        *p++ = PHY_LED_BTNESS;
        *p++ = 1;
        *p++ = phy->led_brightness;
    }
    *p++ = PHY_OPTS;
    *p++ = 2;
    p += put_uint16_t_be(phy->opts, p);
    if (phy->up_btn_present) {
        *p++ = PHY_UP_BTN;
        *p++ = 1;
        *p++ = phy->up_btn;
    }
    if (phy->usb_product_present) {
        *p++ = PHY_USB_PRODUCT;
        *p++ = (uint8_t)strlen(phy->usb_product) + 1;
        strcpy((char *)p, phy->usb_product);
        p += strlen(phy->usb_product);
        *p++ = '\0';
    }
    if (phy->enabled_curves_present) {
        *p++ = PHY_ENABLED_CURVES;
        *p++ = 4;
        p += put_uint32_t_be(phy->enabled_curves, p);
    }
    if (phy->enabled_usb_itf_present) {
        *p++ = PHY_ENABLED_USB_ITF;
        *p++ = 1;
        *p++ = phy->enabled_usb_itf;
    }
    if (phy->led_driver_present) {
        *p++ = PHY_LED_DRIVER;
        *p++ = 1;
        *p++ = phy->led_driver;
    }

    *len = (uint8_t)(p - data);
    return PICOKEY_OK;
}

int phy_unserialize_data(const uint8_t *data, uint16_t len, phy_data_t *phy) {
    if (!phy || !data || !len) {
        return PICOKEY_ERR_NULL_PARAM;
    }
    const uint8_t *p = data;
    uint8_t tag, tlen;
    while (p < data + len) {
        tag = *p++;
        tlen = *p++;
        switch (tag) {
            case PHY_VIDPID:
                if (tlen == 4) {
                    memcpy(phy->vidpid, p, 4);
                    phy->vidpid[1] = *p++;
                    phy->vidpid[0] = *p++;
                    phy->vidpid[3] = *p++;
                    phy->vidpid[2] = *p++;
                    phy->vidpid_present = true;
                }
                break;
            case PHY_LED_GPIO:
                if (tlen == 1) {
                    phy->led_gpio = *p++;
                    phy->led_gpio_present = true;
                }
                break;
            case PHY_LED_BTNESS:
                if (tlen == 1) {
                    phy->led_brightness = *p++;
                    phy->led_brightness_present = true;
                }
                break;
            case PHY_OPTS:
                if (tlen == 2) {
                    phy->opts = get_uint16_t_be(p);
                    p += 2;
                }
                break;
            case PHY_UP_BTN:
                if (tlen == 1) {
                    phy->up_btn = *p++;
                    phy->up_btn_present = true;
                }
                break;
            case PHY_USB_PRODUCT:
                if (tlen > 0 && tlen <= sizeof(phy->usb_product)) {
                    memset(phy->usb_product, 0, sizeof(phy->usb_product));
                    strlcpy(phy->usb_product, (const char *)p, sizeof(phy->usb_product));
                    phy->usb_product_present = true;
                    p += strlen(phy->usb_product) + 1;
                }
                break;
            case PHY_ENABLED_CURVES:
                if (tlen == 4) {
                    phy->enabled_curves = get_uint32_t_be(p);
                    p += 4;
                    phy->enabled_curves_present = true;
                }
                break;

            case PHY_ENABLED_USB_ITF:
                if (tlen == 1) {
                    phy->enabled_usb_itf = *p++;
                    phy->enabled_usb_itf_present = true;
                }
                break;
            case PHY_LED_DRIVER:
                if (tlen == 1) {
                    phy->led_driver = *p++;
                    phy->led_driver_present = true;
                }
                break;
            default:
                p += tlen;
                break;
        }
    }
    if (!phy_data.enabled_usb_itf_present) {
        phy_data.enabled_usb_itf = PHY_USB_ITF_CCID | PHY_USB_ITF_WCID | PHY_USB_ITF_HID | PHY_USB_ITF_KB;
        phy_data.enabled_usb_itf_present = true;
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
