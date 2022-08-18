
/*
 * This file is part of the Pico CCID distribution (https://github.com/polhenarejos/pico-ccid).
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
#include "ccid_version.h"

#include <stdio.h>

// Pico
#include "pico/stdlib.h"
#include "tusb.h"
#include "device/usbd_pvt.h"
#include "usb_descriptors.h"

// For memcpy
#include <string.h>
#include <stdlib.h>

// Device specific functions
static uint8_t rx_buffer[4096], tx_buffer[4096];
static uint16_t w_offset = 0, r_offset = 0;
static uint8_t itf_num;
static uint16_t w_len = 0, tx_r_offset = 0;

uint32_t usb_write_offset(uint16_t len, uint16_t offset) {
    uint8_t pkt_max = 64;
    if (len > sizeof(tx_buffer))
        len = sizeof(tx_buffer);
    w_len = len;
    tx_r_offset = offset;
    tud_vendor_write(tx_buffer+offset, MIN(len, pkt_max));
    w_len -= MIN(len, pkt_max);
    tx_r_offset += MIN(len, pkt_max);
    return MIN(w_len, pkt_max);
}

uint32_t usb_write_flush() {
    if (w_len > 0 && tud_vendor_write_available() > 0) {
        //printf("w_len %d %d %ld\r\n",w_len,tx_r_offset,tud_vendor_write_available());
        tud_vendor_write(tx_buffer+tx_r_offset, MIN(w_len, 64));
        tx_r_offset += MIN(w_len, 64);
        w_len -= MIN(w_len, 64);
    }
    return w_len;
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

void tud_vendor_rx_cb(uint8_t itf) {
    (void) itf;
    uint32_t len = tud_vendor_available();
    uint16_t size = MIN(sizeof(rx_buffer)-w_offset, len);
    if (size > 0) {
        size = tud_vendor_read(rx_buffer+w_offset, size);
        w_offset += size;
    }
}

void tud_vendor_tx_cb(uint8_t itf, uint32_t sent_bytes) {
    //printf("written %ld\n",sent_bytes);
    usb_write_flush();
}

#ifndef USB_VID
#define USB_VID   0xFEFF
#endif
#ifndef USB_PID
#define USB_PID   0xFCFD
#endif

#define USB_BCD   0x0200

#define USB_CONFIG_ATT_ONE TU_BIT(7)

#define	MAX_USB_POWER		1

static void ccid_init_cb(void) {
    TU_LOG1("-------- CCID INIT\r\n");
    vendord_init();

    //ccid_notify_slot_change(c);
}

static void ccid_reset_cb(uint8_t rhport) {
    TU_LOG1("-------- CCID RESET\r\n");
    itf_num = 0;
    vendord_reset(rhport);
}

static uint16_t ccid_open(uint8_t rhport, tusb_desc_interface_t const *itf_desc, uint16_t max_len) {
    uint8_t *itf_vendor = (uint8_t *)malloc(sizeof(uint8_t)*max_len);
    TU_LOG1("-------- CCID OPEN\r\n");
    TU_VERIFY(itf_desc->bInterfaceClass == TUSB_CLASS_SMART_CARD && itf_desc->bInterfaceSubClass == 0 && itf_desc->bInterfaceProtocol == 0, 0);

    //vendord_open expects a CLASS_VENDOR interface class
    memcpy(itf_vendor, itf_desc, sizeof(uint8_t)*max_len);
    ((tusb_desc_interface_t *)itf_vendor)->bInterfaceClass = TUSB_CLASS_VENDOR_SPECIFIC;
    vendord_open(rhport, (tusb_desc_interface_t *)itf_vendor, max_len);
    free(itf_vendor);

    uint16_t const drv_len = sizeof(tusb_desc_interface_t) + sizeof(struct ccid_class_descriptor) + 2*sizeof(tusb_desc_endpoint_t);
    TU_VERIFY(max_len >= drv_len, 0);

    itf_num = itf_desc->bInterfaceNumber;
    return drv_len;
}

// Support for parameterized reset via vendor interface control request
static bool ccid_control_xfer_cb(uint8_t __unused rhport, uint8_t stage, tusb_control_request_t const * request) {
    // nothing to do with DATA & ACK stage
    TU_LOG2("-------- CCID CTRL XFER\r\n");
    if (stage != CONTROL_STAGE_SETUP) return true;

    if (request->wIndex == itf_num)
    {
        TU_LOG2("-------- bmRequestType %x, bRequest %x, wValue %x, wLength %x\r\n",request->bmRequestType,request->bRequest, request->wValue, request->wLength);
/*
#if PICO_STDIO_USB_RESET_INTERFACE_SUPPORT_RESET_TO_BOOTSEL
        if (request->bRequest == RESET_REQUEST_BOOTSEL) {
#ifdef PICO_STDIO_USB_RESET_BOOTSEL_ACTIVITY_LED
            uint gpio_mask = 1u << PICO_STDIO_USB_RESET_BOOTSEL_ACTIVITY_LED;
#else
            uint gpio_mask = 0u;
#endif
#if !PICO_STDIO_USB_RESET_BOOTSEL_FIXED_ACTIVITY_LED
            if (request->wValue & 0x100) {
                gpio_mask = 1u << (request->wValue >> 9u);
            }
#endif
            reset_usb_boot(gpio_mask, (request->wValue & 0x7f) | PICO_STDIO_USB_RESET_BOOTSEL_INTERFACE_DISABLE_MASK);
            // does not return, otherwise we'd return true
        }
#endif
#if PICO_STDIO_USB_RESET_INTERFACE_SUPPORT_RESET_TO_FLASH_BOOT
        if (request->bRequest == RESET_REQUEST_FLASH) {
            watchdog_reboot(0, 0, PICO_STDIO_USB_RESET_RESET_TO_FLASH_DELAY_MS);
            return true;
        }
#endif
*/
        return true;
    }
    return false;
}

static bool ccid_xfer_cb(uint8_t rhport, uint8_t ep_addr, xfer_result_t result, uint32_t xferred_bytes) {
    //printf("------ CALLED XFER_CB\r\n");
    return vendord_xfer_cb(rhport, ep_addr, result, xferred_bytes);
    //return true;
}

static const usbd_class_driver_t ccid_driver = {
#if CFG_TUSB_DEBUG >= 2
    .name = "CCID",
#endif
    .init             = ccid_init_cb,
    .reset            = ccid_reset_cb,
    .open             = ccid_open,
    .control_xfer_cb  = ccid_control_xfer_cb,
    .xfer_cb          = ccid_xfer_cb,
    .sof              = NULL
};

// Implement callback to add our custom driver
usbd_class_driver_t const *usbd_app_driver_get_cb(uint8_t *driver_count) {
    *driver_count = 1;
    return &ccid_driver;
}
