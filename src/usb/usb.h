/*
 * This file is part of the Pico HSM distribution (https://github.com/polhenarejos/pico-hsm).
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

#ifndef _USB_H_
#define _USB_H_

#include "pico/util/queue.h"

/* USB thread */
#define EV_CARD_CHANGE        1
#define EV_TX_FINISHED        2
#define EV_EXEC_ACK_REQUIRED  4
#define EV_EXEC_FINISHED      8
#define EV_RX_DATA_READY     16
#define EV_PRESS_BUTTON      32

/* Card thread */
#define EV_MODIFY_CMD_AVAILABLE   1
#define EV_VERIFY_CMD_AVAILABLE   2
#define EV_CMD_AVAILABLE          4
#define EV_EXIT                   8
#define EV_BUTTON_TIMEOUT        16
#define EV_BUTTON_PRESSED        32

extern void usb_task();
extern queue_t usb_to_card_q;
extern queue_t card_to_usb_q;
extern int driver_process_usb_packet(uint16_t rx_read);
extern void driver_exec_finished(size_t size_next);
extern void driver_exec_finished_cont(size_t size_next, size_t offset);
extern void driver_exec_timeout();
extern bool driver_mounted();
extern uint8_t *driver_prepare_response();

extern void card_start();
extern void card_exit();
extern void usb_init();
extern uint8_t *usb_prepare_response();
extern void timeout_stop();
extern void timeout_start();
extern uint8_t *usb_get_rx();
extern uint8_t *usb_get_tx();
extern uint32_t usb_write_offset(uint16_t len, uint16_t offset);
extern void usb_clear_rx();
#endif
