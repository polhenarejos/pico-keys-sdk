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
#else
#include "emulation.h"
#endif

// For memcpy
#include <string.h>
#include <stdlib.h>

// Device specific functions
static uint32_t timeout_counter[ITF_TOTAL] = { 0 };
static uint8_t card_locked_itf = ITF_TOTAL; // no locked
static void (*card_locked_func)(void) = NULL;
#ifndef ENABLE_EMULATION
static mutex_t mutex;
#endif

void usb_set_timeout_counter(uint8_t itf, uint32_t v) {
    timeout_counter[itf] = v;
}

queue_t usb_to_card_q = {0};
queue_t card_to_usb_q = {0};

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
            if (opts & PHY_OPT_DIMM) {
                led_dimmable = true;
            }
        }
        if (file_get_size(ef_phy) >= 4 && opts & PHY_OPT_VPID) {
            desc_device.idVendor = (data[PHY_VID] << 8) | data[PHY_VID+1];
            desc_device.idProduct = (data[PHY_PID] << 8) | data[PHY_PID+1];
        }
        if (opts & PHY_OPT_BTNESS) {
            led_phy_btness = data[PHY_LED_BTNESS];
        }
    }
    mutex_init(&mutex);
#endif
    queue_init(&card_to_usb_q, sizeof(uint32_t), 64);
    queue_init(&usb_to_card_q, sizeof(uint32_t), 64);
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
#ifndef ENABLE_EMULATION
    mutex_enter_blocking(&mutex);
#endif
    queue_add_blocking(&usb_to_card_q, &flag);
    if (flag == EV_CMD_AVAILABLE) {
        timeout_start();
    }
    uint32_t m;
    queue_remove_blocking(&card_to_usb_q , &m);
#ifndef ENABLE_EMULATION
    mutex_exit(&mutex);
#endif
}

extern void low_flash_init();
void card_init_core1() {
    low_flash_init_core1();
}

uint16_t finished_data_size = 0;

void card_start(uint8_t itf, void (*func)(void)) {
    timeout_start();
    if (card_locked_itf != itf || card_locked_func != func) {
        if (card_locked_itf != ITF_TOTAL || card_locked_func != NULL) {
            card_exit();
        }
        if (func) {
            multicore_reset_core1();
            multicore_launch_core1(func);
        }
        led_set_mode(MODE_MOUNTED);
        card_locked_itf = itf;
        card_locked_func = func;
    }
}

void card_exit() {
    if (card_locked_itf != ITF_TOTAL || card_locked_func != NULL) {
        usb_send_event(EV_EXIT);
        uint32_t m;
        while (queue_is_empty(&usb_to_card_q) == false) {
            if (queue_try_remove(&usb_to_card_q, &m) == false) {
                break;
            }
        }
        while (queue_is_empty(&card_to_usb_q) == false) {
#ifndef ENABLE_EMULATION
            mutex_enter_blocking(&mutex);
#endif
            if (queue_try_remove(&card_to_usb_q, &m) == false) {
                break;
            }
#ifndef ENABLE_EMULATION
            mutex_exit(&mutex);
#endif
        }
        led_set_mode(MODE_SUSPENDED);
#ifdef ESP_PLATFORM
        hcore1 = NULL;
#endif
    }
    card_locked_itf = ITF_TOTAL;
    card_locked_func = NULL;
}
extern void hid_task();
extern void ccid_task();
extern void emul_task();
void usb_task() {
#ifdef USB_ITF_HID
    hid_task();
#endif
#ifdef ENABLE_EMULATION
    emul_task();
#else
#ifdef USB_ITF_CCID
    ccid_task();
#endif
#endif
}

int card_status(uint8_t itf) {
    if (card_locked_itf == itf) {
        uint32_t m = 0x0;
#ifndef ENABLE_EMULATION
        mutex_enter_blocking(&mutex);
#endif
        bool has_m = queue_try_remove(&card_to_usb_q, &m);
#ifndef ENABLE_EMULATION
        mutex_exit(&mutex);
#endif
        //if (m != 0)
        //    printf("\n ------ M = %lu\n",m);
        if (has_m) {
            if (m == EV_EXEC_FINISHED) {
                timeout_stop();
                led_set_mode(MODE_MOUNTED);
                return CCID_OK;
            }
#ifndef ENABLE_EMULATION
            else if (m == EV_PRESS_BUTTON) {
                uint32_t flag = wait_button() ? EV_BUTTON_TIMEOUT : EV_BUTTON_PRESSED;
                queue_try_add(&usb_to_card_q, &flag);
            }
#endif
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
    return CCID_ERR_FILE_NOT_FOUND;
}
