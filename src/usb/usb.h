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

#ifndef _USB_H_
#define _USB_H_

#if defined(ENABLE_EMULATION)
#include "emulation.h"
#elif defined(ESP_PLATFORM)
#include "esp_compat.h"
#else
#include "pico/util/queue.h"
#endif

#include "compat.h"

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
    ITF_HID_CTAP = 0,
    ITF_HID_KB,
#endif
    ITF_HID_TOTAL
};
enum {
#ifdef USB_ITF_CCID
    ITF_SC_CCID = 0,
    ITF_SC_WCID,
#endif
    ITF_SC_TOTAL
};

enum {
#ifdef USB_ITF_HID
    ITF_HID = ITF_HID_CTAP,
    ITF_KEYBOARD = ITF_HID_KB,
#endif
#ifdef USB_ITF_CCID
    ITF_CCID = ITF_SC_CCID + ITF_HID_TOTAL,
    ITF_WCID = ITF_SC_WCID + ITF_HID_TOTAL,
#endif
    ITF_TOTAL = ITF_HID_TOTAL + ITF_SC_TOTAL
};

enum {
    REPORT_ID_KEYBOARD = 0,
    REPORT_ID_COUNT
};

#if defined(ESP_PLATFORM) && defined(USB_ITF_HID) && defined(USB_ITF_CCID)
#define TUSB_SMARTCARD_CCID_EPS 2
#else
#define TUSB_SMARTCARD_CCID_EPS 3
#endif

extern void usb_task();
extern queue_t usb_to_card_q;
extern queue_t card_to_usb_q;

extern void card_start(uint8_t, void (*func)(void));
extern void card_exit();
extern int card_status(uint8_t itf);
extern void usb_init();

extern uint16_t finished_data_size;
extern void usb_set_timeout_counter(uint8_t itf, uint32_t v);
extern void card_init_core1();

extern void usb_send_event(uint32_t flag);
extern void timeout_stop();
extern void timeout_start();
extern bool is_busy();

#ifdef USB_ITF_HID
extern void driver_exec_finished_hid(uint16_t size_next);
extern void driver_exec_finished_cont_hid(uint8_t itf, uint16_t size_next, uint16_t offset);
#endif

#ifdef USB_ITF_CCID
extern void driver_exec_finished_ccid(uint8_t itf, uint16_t size_next);
extern void driver_exec_finished_cont_ccid(uint8_t itf, uint16_t size_next, uint16_t offset);
#endif

#ifdef ENABLE_EMULATION
extern void driver_exec_finished_emul(uint8_t itf, uint16_t size_next);
extern void driver_exec_finished_cont_emul(uint8_t itf, uint16_t size_next, uint16_t offset);
#endif

#define USB_BUFFER_SIZE         2048

PACK(
typedef struct {
    uint8_t buffer[USB_BUFFER_SIZE];
    uint16_t r_ptr;
    uint16_t w_ptr;
}) usb_buffer_t;

typedef enum {
    WRITE_UNKNOWN = 0,
    WRITE_PENDING,
    WRITE_FAILED,
    WRITE_SUCCESS,
} write_status_t;

#endif
