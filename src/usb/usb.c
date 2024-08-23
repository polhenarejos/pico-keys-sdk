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

#include <stdio.h>

// Pico
#if !defined(ENABLE_EMULATION) && !defined(ESP_PLATFORM)
#include "pico/stdlib.h"
#include "pico/multicore.h"
#include "bsp/board.h"
#endif
#include "pico_keys.h"
#include "usb.h"
#include "apdu.h"
#ifndef ENABLE_EMULATION
#include "tusb.h"
#endif

// For memcpy
#include <string.h>
#include <stdlib.h>

// Device specific functions
static uint32_t timeout_counter[ITF_TOTAL] = { 0 };
uint8_t card_locked_itf = ITF_TOTAL; // no locked

void usb_set_timeout_counter(uint8_t itf, uint32_t v) {
    timeout_counter[itf] = v;
}

#if !defined(ENABLE_EMULATION)
queue_t usb_to_card_q;
queue_t card_to_usb_q;
#endif

#ifndef ENABLE_EMULATION
extern tusb_desc_device_t desc_device;
extern bool enable_wcid;
#endif
void usb_init() {
#ifndef ENABLE_EMULATION
    if (file_has_data(ef_phy)) {
        uint8_t *data = file_get_data(ef_phy);
        uint16_t opts = 0;
        if (file_get_size(ef_phy) >= 8) {
            opts = (data[PHY_OPTS] << 8) | data[PHY_OPTS+1];
            if (opts & PHY_OPT_WCID) {
                enable_wcid = true;
            }
        }
        if (file_get_size(ef_phy) >= 4 && opts & PHY_OPT_VPID) {
            desc_device.idVendor = (data[PHY_VID] << 8) | data[PHY_VID+1];
            desc_device.idProduct = (data[PHY_PID] << 8) | data[PHY_PID+1];
        }
    }

    queue_init(&card_to_usb_q, sizeof(uint32_t), 64);
    queue_init(&usb_to_card_q, sizeof(uint32_t), 64);
#endif
}

uint32_t timeout = 0;
void timeout_stop() {
    timeout = 0;
}

void timeout_start() {
    timeout = board_millis();
}

bool is_busy() {
    return timeout > 0;
}

void usb_send_event(uint32_t flag) {
    queue_add_blocking(&usb_to_card_q, &flag);
    if (flag == EV_CMD_AVAILABLE) {
        timeout_start();
    }
}

extern void low_flash_init();
void card_init_core1() {
#ifndef ENABLE_EMULATION
    low_flash_init_core1();
#endif
}

uint16_t finished_data_size = 0;

void card_start(uint8_t itf, void (*func)(void)) {
    timeout_start();
    if (card_locked_itf != itf) {
#ifndef ENABLE_EMULATION
        uint32_t m = 0;
        while (queue_is_empty(&usb_to_card_q) == false) {
            if (queue_try_remove(&usb_to_card_q, &m) == false) {
                break;
            }
        }
        while (queue_is_empty(&card_to_usb_q) == false) {
            if (queue_try_remove(&card_to_usb_q, &m) == false) {
                break;
            }
        }
        multicore_reset_core1();
        if (func) {
            multicore_launch_core1(func);
        }
        led_set_blink(BLINK_MOUNTED);
#else
        (void)func;
#endif
        card_locked_itf = itf;
    }
}

void card_exit() {
#ifndef ENABLE_EMULATION
    uint32_t flag = EV_EXIT;
    queue_try_add(&usb_to_card_q, &flag);
    led_set_blink(BLINK_SUSPENDED);
    multicore_reset_core1();
#ifdef ESP_PLATFORM
    hcore1 = NULL;
#endif
    card_locked_itf = ITF_TOTAL;
#endif
}
extern void hid_task();
extern void ccid_task();
void usb_task() {
#ifndef ENABLE_EMULATION
#ifdef USB_ITF_HID
    hid_task();
#endif
#ifdef USB_ITF_CCID
    ccid_task();
#endif
#endif
}

int card_status(uint8_t itf) {
#ifndef ENABLE_EMULATION
    if (card_locked_itf == itf) {
        uint32_t m = 0x0;
        bool has_m = queue_try_remove(&card_to_usb_q, &m);
        //if (m != 0)
        //    printf("\n ------ M = %lu\n",m);
        if (has_m) {
            if (m == EV_EXEC_FINISHED) {
                timeout_stop();
                led_set_blink(BLINK_MOUNTED);
                card_locked_itf = ITF_TOTAL;
                return CCID_OK;
            }
            else if (m == EV_PRESS_BUTTON) {
                uint32_t flag = wait_button() ? EV_BUTTON_TIMEOUT : EV_BUTTON_PRESSED;
                queue_try_add(&usb_to_card_q, &flag);
            }
            return CCID_ERR_FILE_NOT_FOUND;
        }
        else {
            if (timeout > 0) {
                if (timeout + timeout_counter[itf] < board_millis()) {
                    timeout = board_millis();
                    return CCID_ERR_BLOCKED;
                }
            }
        }
    }
#endif
    return CCID_ERR_FILE_NOT_FOUND;
}

uint8_t *usb_prepare_response(uint8_t itf) {
#ifndef ENABLE_EMULATION
#ifdef USB_ITF_CCID
#endif
    return NULL;
#else
    return driver_prepare_response_emul(itf);
#endif
}
