
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

#include "pico/unique_id.h"

#include <stdio.h>

// Pico
#include "pico/stdlib.h"
#include "pico/multicore.h"
#include "tusb.h"
#include "hsm.h"
#include "usb.h"
#include "apdu.h"

#include "bsp/board.h"

// For memcpy
#include <string.h>
#include <stdlib.h>

// Device specific functions
static uint8_t rx_buffer[4096], tx_buffer[4096+64];
static uint16_t w_offset = 0, r_offset = 0;
static uint16_t w_len = 0, tx_r_offset = 0;
static uint32_t timeout_counter = 0;

void usb_set_timeout_counter(uint32_t v) {
    timeout_counter = v;
}

uint32_t usb_write_offset(uint16_t len, uint16_t offset) {
    uint8_t pkt_max = 64;
    int w = 0;
    if (len > sizeof(tx_buffer))
        len = sizeof(tx_buffer);
    w_len = len;
    tx_r_offset = offset;
    w = driver_write(tx_buffer+offset, MIN(len, pkt_max));
    w_len -= w;
    tx_r_offset += w;
    return w;
}

size_t usb_rx(const uint8_t *buffer, size_t len) {
    uint16_t size = MIN(sizeof(rx_buffer) - w_offset, len);
    if (size > 0) {
        if (buffer == NULL)
            size = driver_read(rx_buffer + w_offset, size);
        else
            memcpy(rx_buffer + w_offset, buffer, size);
        w_offset += size;
    }
    return size;
}

uint32_t usb_write_flush() {
    int w = 0;
    if (w_len > 0 && tud_vendor_write_available() > 0) {
        w = driver_write(tx_buffer+tx_r_offset, MIN(w_len, 64));
        tx_r_offset += w;
        w_len -= w;
    }
    return w;
}

uint32_t usb_write(uint16_t len) {
    return usb_write_offset(len, 0);
}

uint16_t usb_read_available() {
    return w_offset - r_offset;
}

uint16_t usb_write_available() {
    return w_len > 0;
}

uint8_t *usb_get_rx() {
    return rx_buffer;
}

uint8_t *usb_get_tx() {
    return tx_buffer;
}

void usb_clear_rx() {
    w_offset = r_offset = 0;
}

uint16_t usb_read(uint8_t *buffer, size_t buffer_size) {
    uint16_t size = MIN(buffer_size, w_offset-r_offset);
    if (size > 0) {
        memcpy(buffer, rx_buffer+r_offset, size);
        r_offset += size;
        if (r_offset == w_offset) {
            r_offset = w_offset = 0;
        }
        return size;
    }
    return 0;
}

#ifndef USB_VID
#define USB_VID   0xFEFF
#endif
#ifndef USB_PID
#define USB_PID   0xFCFD
#endif

#define USB_BCD   0x0200

uint32_t timeout = 0;

queue_t usb_to_card_q;
queue_t card_to_usb_q;

void usb_init() {
    queue_init(&card_to_usb_q, sizeof(uint32_t), 64);
    queue_init(&usb_to_card_q, sizeof(uint32_t), 64);
    driver_init();
}

extern int driver_process_usb_nopacket();

static int usb_event_handle() {
    uint16_t rx_read = usb_read_available();
    if (driver_process_usb_packet(rx_read) > 0) {
        uint32_t flag = EV_CMD_AVAILABLE;
        queue_add_blocking(&usb_to_card_q, &flag);
        timeout_start();
    }
    else
        driver_process_usb_nopacket();

    return 0;
}

extern void low_flash_init();
void card_init_core1() {
    low_flash_init_core1();
}

size_t finished_data_size = 0;

void card_start(void (*func)(void)) {
    multicore_reset_core1();
    multicore_launch_core1(func);
    led_set_blink(BLINK_MOUNTED);
}

void card_exit() {
    uint32_t flag = EV_EXIT;
    queue_try_add(&usb_to_card_q, &flag);
    led_set_blink(BLINK_SUSPENDED);
}

void usb_task() {
    if (driver_mounted()) {
        if (usb_event_handle() != 0) {

        }
        usb_write_flush();
        uint32_t m = 0x0;
        bool has_m = queue_try_remove(&card_to_usb_q, &m);
        //if (m != 0)
        //    printf("\r\n ------ M = %lu\r\n",m);
        if (has_m) {
            if (m == EV_EXEC_FINISHED) {
                driver_exec_finished(finished_data_size);
                led_set_blink(BLINK_MOUNTED);
                timeout_stop();
            }
            else if (m == EV_PRESS_BUTTON) {
        	    uint32_t flag = wait_button() ? EV_BUTTON_TIMEOUT : EV_BUTTON_PRESSED;
        	    queue_try_add(&usb_to_card_q, &flag);
        	}
            /*
            if (m == EV_RX_DATA_READY) {
        	    c->ccid_state = ccid_handle_data(c);
        	    timeout = 0;
        	    c->timeout_cnt = 0;
        	}
            else if (m == EV_EXEC_FINISHED) {
	            if (c->ccid_state == CCID_STATE_EXECUTE) {
	                exec_done:
            	    if (c->a->sw == CCID_THREAD_TERMINATED) {
                		c->sw1sw2[0] = 0x90;
                		c->sw1sw2[1] = 0x00;
                		c->state = APDU_STATE_RESULT;
                		ccid_send_data_block(c);
                		c->ccid_state = CCID_STATE_EXITED;
                		c->application = 0;
                		return;
            	    }

            	    c->a->cmd_apdu_data_len = 0;
            	    c->sw1sw2[0] = c->a->sw >> 8;
            	    c->sw1sw2[1] = c->a->sw & 0xff;
            	    if (c->a->res_apdu_data_len <= c->a->expected_res_size) {
                		c->state = APDU_STATE_RESULT;
                		ccid_send_data_block(c);
                		c->ccid_state = CCID_STATE_WAIT;
            	    }
            	    else {
                		c->state = APDU_STATE_RESULT_GET_RESPONSE;
                		c->p = c->a->res_apdu_data;
                		c->len = c->a->res_apdu_data_len;
                		ccid_send_data_block_gr(c, c->a->expected_res_size);
                		c->ccid_state = CCID_STATE_WAIT;
            	    }
            	}
            	else {
        	        DEBUG_INFO ("ERR05\r\n");
        	    }
        	    led_set_blink(BLINK_MOUNTED);
            }
            else if (m == EV_TX_FINISHED){
        	    if (c->state == APDU_STATE_RESULT)
        	        ccid_reset(c);
        	    else
        	        c->tx_busy = 0;
        	    if (c->state == APDU_STATE_WAIT_COMMAND || c->state == APDU_STATE_COMMAND_CHAINING || c->state == APDU_STATE_RESULT_GET_RESPONSE)
        	        ccid_prepare_receive(c);
        	}
        	*/
        }
        else {
            if (timeout > 0) {
                if (timeout + timeout_counter < board_millis()) {
                    driver_exec_timeout();
                    timeout = board_millis();
                }
            }
        }
    }
}

void timeout_stop() {
    timeout = 0;
}

void timeout_start() {
    timeout = board_millis();
}

uint8_t *usb_prepare_response() {
    return driver_prepare_response();
}