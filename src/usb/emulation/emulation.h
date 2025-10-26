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

#ifndef _EMULATION_H_
#define _EMULATION_H_

#include <stdint.h>
#include <string.h>
#include "queue.h"
#include "board.h"
#include <stdbool.h>

#define USB_BUFFER_SIZE 2048
extern int emul_init(char *host, uint16_t port);
extern uint8_t emul_rx[USB_BUFFER_SIZE];
extern uint16_t emul_rx_size, emul_tx_size;
extern uint16_t driver_write_emul(uint8_t itf, const uint8_t *buffer, uint16_t buffer_size);
extern uint16_t emul_read(uint8_t itf);

#ifdef USB_ITF_HID
typedef uint8_t hid_report_type_t;
#endif

#ifdef USB_ITF_CCID
static inline uint32_t tud_vendor_n_available(uint8_t itf) {
    (void) itf;
    return emul_rx_size;
}
static inline uint32_t tud_vendor_n_read(uint8_t itf, uint8_t *buffer, uint32_t n) {
    (void) itf;
    if (n > emul_rx_size) {
        n = emul_rx_size;
    }
    memcpy(buffer, emul_rx, n);
    emul_rx_size = 0;
    return n;
}
extern void tud_vendor_tx_cb(uint8_t itf, uint32_t sent_bytes);
extern uint32_t tud_vendor_n_write(uint8_t itf, const uint8_t *buffer, uint32_t n);
static inline uint32_t tud_vendor_n_flush(uint8_t itf) {
    (void) itf;
    return emul_tx_size;
}
#endif

#ifdef USB_ITF_HID
extern void tud_hid_report_complete_cb(uint8_t instance, uint8_t const *report, uint16_t len);
extern bool tud_hid_n_report(uint8_t itf, uint8_t report_id, const uint8_t *buffer, uint32_t n);
#endif

#endif // _EMULATION_H_
