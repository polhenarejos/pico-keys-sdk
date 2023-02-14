/*
 * This file is part of the Pico HSM SDK distribution (https://github.com/polhenarejos/pico-hsm-sdk).
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
#ifndef ENABLE_EMULATION
#include "pico/stdlib.h"
#include "pico/multicore.h"
#include "tusb.h"
#include "bsp/board.h"
#endif
#include "hsm.h"
#include "usb.h"
#include "apdu.h"

// For memcpy
#include <string.h>
#include <stdlib.h>

// Device specific functions
static uint8_t rx_buffer[ITF_TOTAL][4096] = { 0 }, tx_buffer[ITF_TOTAL][4096+64] = { 0 };
static uint16_t w_offset[ITF_TOTAL] = { 0 }, r_offset[ITF_TOTAL] = { 0 };
static uint16_t w_len[ITF_TOTAL] = { 0 }, tx_r_offset[ITF_TOTAL] = { 0 };
static uint32_t timeout_counter[ITF_TOTAL] = { 0 };
uint8_t card_locked_itf = ITF_TOTAL; // no locked

void usb_set_timeout_counter(uint8_t itf, uint32_t v)
{
    timeout_counter[itf] = v;
}

uint32_t usb_write_offset(uint8_t itf, uint16_t len, uint16_t offset)
{
#ifndef ENABLE_EMULATION
    uint8_t pkt_max = 64;
#endif
    int w = 0;
    if (len > sizeof(tx_buffer[itf])) {
        len = sizeof(tx_buffer[itf]);
    }
    w_len[itf] = len;
    tx_r_offset[itf] = offset;
#ifdef USB_ITF_HID
    if (itf == ITF_HID) {
        w = driver_write_hid(tx_buffer[itf]+offset, MIN(len, pkt_max));
    }
#endif
#ifdef USB_ITF_CCID
    if (itf == ITF_CCID) {
        w = driver_write_ccid(tx_buffer[itf]+offset, MIN(len, pkt_max));
    }
#endif
#ifdef ENABLE_EMULATION
    if (itf == ITF_EMUL) {
        w = driver_write_emul(tx_buffer[itf]+offset, len);
    }
#endif
    w_len[itf] -= w;
    tx_r_offset[itf] += w;
    return w;
}

size_t usb_rx(uint8_t itf, const uint8_t *buffer, size_t len)
{
    uint16_t size = MIN(sizeof(rx_buffer[itf]) - w_offset[itf], len);
    if (size > 0) {
        if (buffer == NULL) {
#ifdef USB_ITF_HID
            if (itf == ITF_HID) {
                size = driver_read_hid(rx_buffer[itf] + w_offset[itf], size);
            }
#endif
#ifdef USB_ITF_CCID
            if (itf == ITF_CCID) {
                size = driver_read_ccid(rx_buffer[itf] + w_offset[itf], size);
            }
#endif
        } else {
            memcpy(rx_buffer[itf] + w_offset[itf], buffer, size);
        }
        w_offset[itf] += size;
    }
    return size;
}

uint32_t usb_write_flush(uint8_t itf)
{
    int w = 0;
    if (w_len[itf] > 0) {
#ifdef USB_ITF_HID
        if (itf == ITF_HID) {
            w = driver_write_hid(tx_buffer[itf]+tx_r_offset[itf], MIN(w_len[itf], 64));
        }
#endif
#ifdef USB_ITF_CCID
        if (itf == ITF_CCID) {
            w = driver_write_ccid(tx_buffer[itf]+tx_r_offset[itf], MIN(w_len[itf], 64));
        }
#endif
#ifdef ENABLE_EMULATION
        if (itf == ITF_EMUL) {
            w = driver_write_emul(tx_buffer[itf]+tx_r_offset[itf], w_len[itf]);
        }
#endif
        tx_r_offset[itf] += w;
        w_len[itf] -= w;
    }
    return w;
}

uint32_t usb_write(uint8_t itf, uint16_t len)
{
    return usb_write_offset(itf, len, 0);
}

uint16_t usb_read_available(uint8_t itf)
{
    return w_offset[itf] - r_offset[itf];
}

uint16_t usb_write_available(uint8_t itf)
{
    return w_len[itf] > 0;
}

uint8_t *usb_get_rx(uint8_t itf)
{
    return rx_buffer[itf];
}

uint8_t *usb_get_tx(uint8_t itf)
{
    return tx_buffer[itf];
}

void usb_clear_rx(uint8_t itf)
{
    w_offset[itf] = r_offset[itf] = 0;
}

#ifndef USB_VID
#define USB_VID   0xFEFF
#endif
#ifndef USB_PID
#define USB_PID   0xFCFD
#endif

#define USB_BCD   0x0200

#ifndef ENABLE_EMULATION
queue_t usb_to_card_q;
queue_t card_to_usb_q;
#endif

void usb_init()
{
#ifndef ENABLE_EMULATION
    queue_init(&card_to_usb_q, sizeof(uint32_t), 64);
    queue_init(&usb_to_card_q, sizeof(uint32_t), 64);
#endif
}

extern int driver_process_usb_nopacket();
extern uint32_t timeout;

static int usb_event_handle(uint8_t itf)
{
#ifndef ENABLE_EMULATION
    uint16_t rx_read = usb_read_available(itf);
#else
    uint16_t rx_read = emul_read();
#endif
    int proc_packet = 0;
#ifdef USB_ITF_HID
    if (itf == ITF_HID) {
        proc_packet = driver_process_usb_packet_hid(rx_read);
    }
#endif
#ifdef USB_ITF_CCID
    if (itf == ITF_CCID) {
        proc_packet = driver_process_usb_packet_ccid(rx_read);
    }
#endif
#ifdef ENABLE_EMULATION
    if (itf == ITF_EMUL) {
        proc_packet = driver_process_usb_packet_emul(rx_read);
    }
#endif
    if (proc_packet > 0) {
        card_locked_itf = itf;
#ifndef ENABLE_EMULATION
        uint32_t flag = EV_CMD_AVAILABLE;
        queue_add_blocking(&usb_to_card_q, &flag);
#endif
        timeout_start();
    } else {
#ifdef USB_ITF_HID
        if (itf == ITF_HID) {
            driver_process_usb_nopacket_hid();
        }
#endif
#ifdef USB_ITF_CCID
        if (itf == ITF_CCID) {
            driver_process_usb_nopacket_ccid();
        }
#endif
    }
    return 0;
}

extern void low_flash_init();
void card_init_core1()
{
#ifndef ENABLE_EMULATION
    low_flash_init_core1();
#endif
}

size_t finished_data_size = 0;

void card_start(void (*func)(void))
{
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
    multicore_launch_core1(func);
    led_set_blink(BLINK_MOUNTED);
#endif
}

void card_exit()
{
#ifndef ENABLE_EMULATION
    uint32_t flag = EV_EXIT;
    queue_try_add(&usb_to_card_q, &flag);
    led_set_blink(BLINK_SUSPENDED);
#endif
    card_locked_itf = ITF_TOTAL;
}
extern void hid_task();
void usb_task()
{
#ifndef ENABLE_EMULATION
    bool mounted = false;
#else
    bool mounted = true;
#endif
    for (uint8_t itf = 0; itf < ITF_TOTAL; itf++) {
#ifdef USB_ITF_HID
        if (itf == ITF_HID) {
            mounted = driver_mounted_hid();
        }
#endif
#ifdef USB_ITF_CCID
        if (itf == ITF_CCID) {
            mounted = driver_mounted_ccid();
        }
#endif

        if (mounted == true) {
            if (usb_event_handle(itf) != 0) {

            }
            usb_write_flush(itf);
#ifndef ENABLE_EMULATION
            if (card_locked_itf == itf) {
                uint32_t m = 0x0;
                bool has_m = queue_try_remove(&card_to_usb_q, &m);
                //if (m != 0)
                //    printf("\r\n ------ M = %lu\r\n",m);
                if (has_m) {
                    if (m == EV_EXEC_FINISHED) {
                        timeout_stop();
#ifdef USB_ITF_HID
                        if (itf == ITF_HID) {
                            driver_exec_finished_hid(finished_data_size);
                        }
#endif
#ifdef USB_ITF_CCID
                        if (itf == ITF_CCID) {
                            driver_exec_finished_ccid(finished_data_size);
                        }
#endif
                        led_set_blink(BLINK_MOUNTED);
                        card_locked_itf = ITF_TOTAL;
                    } else if (m == EV_PRESS_BUTTON) {
                        uint32_t flag = wait_button() ? EV_BUTTON_TIMEOUT : EV_BUTTON_PRESSED;
                        queue_try_add(&usb_to_card_q, &flag);
                    }
                } else {
                    if (timeout > 0) {
                        if (timeout + timeout_counter[itf] < board_millis()) {
    #ifdef USB_ITF_HID
                            if (itf == ITF_HID) {
                                driver_exec_timeout_hid();
                            }
    #endif
    #ifdef USB_ITF_CCID
                            if (itf == ITF_CCID) {
                                driver_exec_timeout_ccid();
                            }
    #endif
                            timeout = board_millis();
                        }
                    }
                }
            }
#endif
        }
    }
#ifdef USB_ITF_HID
    hid_task();
#endif
}


uint8_t *usb_prepare_response(uint8_t itf)
{
#ifdef USB_ITF_HID
    if (itf == ITF_HID) {
        return driver_prepare_response_hid();
    }
#endif
#ifdef USB_ITF_CCID
    if (itf == ITF_CCID) {
        return driver_prepare_response_ccid();
    }
#endif
#ifdef ENABLE_EMULATION
    if (itf == ITF_EMUL) {
        return driver_prepare_response_emul();
    }
#endif
    return NULL;
}
