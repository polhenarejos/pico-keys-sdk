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


enum {
#ifdef USB_ITF_HID
    ITF_HID,
#endif
#ifdef USB_ITF_CCID
    ITF_CCID,
#endif
    ITF_TOTAL
};


extern void usb_task();
extern queue_t usb_to_card_q;
extern queue_t card_to_usb_q;
extern uint8_t card_locked_itf;

#ifdef USB_ITF_HID
extern int driver_process_usb_packet_hid(uint16_t rx_read);
extern void driver_exec_finished_hid(size_t size_next);
extern void driver_exec_finished_cont_hid(size_t size_next, size_t offset);
extern void driver_exec_timeout_hid();
extern bool driver_mounted_hid();
extern uint8_t *driver_prepare_response_hid();
extern int driver_write_hid(const uint8_t *, size_t);
extern size_t driver_read_hid(uint8_t *, size_t);
extern int driver_process_usb_nopacket_hid();
#endif

#ifdef USB_ITF_CCID
extern int driver_process_usb_packet_ccid(uint16_t rx_read);
extern void driver_exec_finished_ccid(size_t size_next);
extern void driver_exec_finished_cont_ccid(size_t size_next, size_t offset);
extern void driver_exec_timeout_ccid();
extern bool driver_mounted_ccid();
extern uint8_t *driver_prepare_response_ccid();
extern int driver_write_ccid(const uint8_t *, size_t);
extern size_t driver_read_ccid(uint8_t *, size_t);
extern int driver_process_usb_nopacket_ccid();
#endif

extern size_t usb_rx(uint8_t itf, const uint8_t *buffer, size_t len);

extern void card_start(void (*func)(void));
extern void card_exit();
extern void usb_init();
extern uint8_t *usb_prepare_response(uint8_t itf);
extern void timeout_stop();
extern void timeout_start();
extern uint8_t *usb_get_rx(uint8_t itf);
extern uint8_t *usb_get_tx(uint8_t itf);
extern uint32_t usb_write_offset(uint8_t itf, uint16_t len, uint16_t offset);
extern void usb_clear_rx(uint8_t itf);
extern size_t finished_data_size;
extern void usb_set_timeout_counter(uint8_t itf, uint32_t v);
extern void card_init_core1();
extern uint32_t usb_write_flush(uint8_t itf);
extern uint16_t usb_read_available(uint8_t itf);

#endif
