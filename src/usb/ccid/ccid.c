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
#include "pico/stdlib.h"

// For memcpy
#include <string.h>

// Include descriptor struct definitions
//#include "usb_common.h"
// USB register definitions from pico-sdk
#include "hardware/regs/usb.h"
// USB hardware struct definitions from pico-sdk
#include "hardware/structs/usb.h"
// For interrupt enable and numbers
#include "hardware/irq.h"
// For resetting the USB controller
#include "hardware/resets.h"

#include "random.h"
#include "hsm.h"
#include "hardware/rtc.h"
#include "tusb.h"
#include "ccid.h"
#include "device/usbd_pvt.h"
#include "usb_descriptors.h"
#include "apdu.h"
#include "usb.h"

const uint8_t *ccid_atr = NULL;

#if MAX_RES_APDU_DATA_SIZE > MAX_CMD_APDU_DATA_SIZE
#define USB_BUF_SIZE (MAX_RES_APDU_DATA_SIZE+20+9)
#else
#define USB_BUF_SIZE (MAX_CMD_APDU_DATA_SIZE+20+9)
#endif

#define CCID_SET_PARAMS		0x61 /* non-ICCD command  */
#define CCID_POWER_ON		0x62
#define CCID_POWER_OFF		0x63
#define CCID_SLOT_STATUS	0x65 /* non-ICCD command */
#define CCID_SECURE		0x69 /* non-ICCD command */
#define CCID_GET_PARAMS		0x6C /* non-ICCD command */
#define CCID_RESET_PARAMS	0x6D /* non-ICCD command */
#define CCID_XFR_BLOCK		0x6F
#define CCID_DATA_BLOCK_RET	0x80
#define CCID_SLOT_STATUS_RET	0x81 /* non-ICCD result */
#define CCID_PARAMS_RET		0x82 /* non-ICCD result */

#define CCID_MSG_SEQ_OFFSET	6
#define CCID_MSG_STATUS_OFFSET	7
#define CCID_MSG_ERROR_OFFSET	8
#define CCID_MSG_CHAIN_OFFSET	9
#define CCID_MSG_DATA_OFFSET	10	/* == CCID_MSG_HEADER_SIZE */
#define CCID_MAX_MSG_DATA_SIZE	USB_BUF_SIZE

#define CCID_STATUS_RUN		0x00
#define CCID_STATUS_PRESENT	0x01
#define CCID_STATUS_NOTPRESENT	0x02
#define CCID_CMD_STATUS_OK	0x00
#define CCID_CMD_STATUS_ERROR	0x40
#define CCID_CMD_STATUS_TIMEEXT	0x80

#define CCID_ERROR_XFR_OVERRUN	0xFC

/*
 * Since command-byte is at offset 0,
 * error with offset 0 means "command not supported".
 */
#define CCID_OFFSET_CMD_NOT_SUPPORTED 0
#define CCID_OFFSET_DATA_LEN 1
#define CCID_OFFSET_PARAM 8

#define CCID_THREAD_TERMINATED 0xffff
#define CCID_ACK_TIMEOUT 0x6600

struct ccid_header {
    uint8_t bMessageType;
    uint32_t dwLength;
    uint8_t bSlot;
    uint8_t bSeq;
    uint8_t abRFU0;
    uint16_t abRFU1;
    uint8_t apdu; //Actually it is an array
} __packed;

uint8_t ccid_status = 1;
static uint8_t itf_num;

void ccid_write_offset(uint16_t size, uint16_t offset) {
    if (*usb_get_tx(ITF_CCID)+offset != 0x81)
        DEBUG_PAYLOAD(usb_get_tx(ITF_CCID)+offset,size+10);
    usb_write_offset(ITF_CCID, size+10, offset);
}

void ccid_write(uint16_t size) {
    ccid_write_offset(size, 0);
}

struct ccid_header *ccid_response;
struct ccid_header *ccid_header;

int driver_init_ccid() {
    ccid_header = (struct ccid_header *)usb_get_rx(ITF_CCID);
    apdu.header = &ccid_header->apdu;

    ccid_response = (struct ccid_header *)usb_get_tx(ITF_CCID);
    apdu.rdata = &ccid_response->apdu;

    usb_set_timeout_counter(ITF_CCID, 1500);

    return CCID_OK;
}

void tud_vendor_rx_cb(uint8_t itf) {
    (void) itf;

    uint32_t len = tud_vendor_available();
    usb_rx(ITF_CCID, NULL, len);
}

void tud_vendor_tx_cb(uint8_t itf, uint32_t sent_bytes) {
    printf("written %ld\n",sent_bytes);
    usb_write_flush(ITF_CCID);
}

int driver_write_ccid(const uint8_t *buffer, size_t buffer_size) {
    return tud_vendor_write(buffer, buffer_size);
}

size_t driver_read_ccid(uint8_t *buffer, size_t buffer_size) {
    return tud_vendor_read(buffer, buffer_size);
}

int driver_process_usb_nopacket_ccid() {
    return 0;
}

int driver_process_usb_packet_ccid(uint16_t rx_read) {
    if (rx_read >= 10) {
        driver_init_ccid();
        //printf("%d %d %x\r\n",tccid->dwLength,rx_read-10,tccid->bMessageType);
        if (ccid_header->dwLength <= rx_read-10) {
            size_t apdu_sent = 0;
            if (ccid_header->bMessageType != 0x65)
                DEBUG_PAYLOAD(usb_get_rx(ITF_CCID),usb_read_available(ITF_CCID));
            if (ccid_header->bMessageType == 0x65) {
                ccid_response->bMessageType = CCID_SLOT_STATUS_RET;
                ccid_response->dwLength = 0;
                ccid_response->bSlot = 0;
                ccid_response->bSeq = ccid_header->bSeq;
                ccid_response->abRFU0 = ccid_status;
                ccid_response->abRFU1 = 0;
                ccid_write(0);
            }
            else if (ccid_header->bMessageType == 0x62) {
                size_t size_atr = (ccid_atr ? ccid_atr[0] : 0);
                ccid_response->bMessageType = 0x80;
                ccid_response->dwLength = size_atr;
                ccid_response->bSlot = 0;
                ccid_response->bSeq = ccid_header->bSeq;
                ccid_response->abRFU0 = 0;
                ccid_response->abRFU1 = 0;
                //printf("1 %x %x %x || %x %x %x\r\n",ccid_response->apdu,apdu.rdata,ccid_response,ccid_header,ccid_header->apdu,apdu.data);
                memcpy(apdu.rdata, ccid_atr+1, size_atr);
                card_start(apdu_thread);
                ccid_status = 0;
                ccid_write(size_atr);
            }
            else if (ccid_header->bMessageType == 0x63) {
                if (ccid_status == 0)
                    card_exit(0);
                ccid_status = 1;
                ccid_response->bMessageType = CCID_SLOT_STATUS_RET;
                ccid_response->dwLength = 0;
                ccid_response->bSlot = 0;
                ccid_response->bSeq = ccid_header->bSeq;
                ccid_response->abRFU0 = ccid_status;
                ccid_response->abRFU1 = 0;
                ccid_write(0);
            }
            else if (ccid_header->bMessageType == 0x6F) {
                apdu_sent = apdu_process(ITF_CCID, &ccid_header->apdu, ccid_header->dwLength);
            }
            usb_clear_rx(ITF_CCID);
            return apdu_sent;
        }
    }
    /*
    if (usb_read_available() && c->epo->ready) {
        if ()
        uint32_t count = usb_read(endp1_rx_buf, sizeof(endp1_rx_buf));
        //if (endp1_rx_buf[0] != 0x65)
            DEBUG_PAYLOAD(endp1_rx_buf, count);
        //DEBUG_PAYLOAD(endp1_rx_buf, count);
        ccid_rx_ready(count);
    }
    */
    return 0;
}

bool driver_mounted_ccid() {
    return tud_vendor_mounted();
}

void driver_exec_timeout_ccid() {
    ccid_response->bMessageType = CCID_DATA_BLOCK_RET;
    ccid_response->dwLength = 0;
    ccid_response->bSlot = 0;
    ccid_response->bSeq = ccid_header->bSeq;
    ccid_response->abRFU0 = CCID_CMD_STATUS_TIMEEXT;
    ccid_response->abRFU1 = 0;
    ccid_write(0);
}

void driver_exec_finished_ccid(size_t size_next) {
    ccid_response->bMessageType = CCID_DATA_BLOCK_RET;
    ccid_response->dwLength = size_next;
    ccid_response->bSlot = 0;
    ccid_response->bSeq = ccid_header->bSeq;
    ccid_response->abRFU0 = ccid_status;
    ccid_response->abRFU1 = 0;
    ccid_write(size_next);
}

void driver_exec_finished_cont_ccid(size_t size_next, size_t offset) {

    ccid_response = (struct ccid_header *)(usb_get_tx(ITF_CCID)+offset-10);
    ccid_response->bMessageType = CCID_DATA_BLOCK_RET;
    ccid_response->dwLength = size_next;
    ccid_response->bSlot = 0;
    ccid_response->bSeq = ccid_header->bSeq;
    ccid_response->abRFU0 = ccid_status;
    ccid_response->abRFU1 = 0;
    ccid_write_offset(size_next, offset-10);
}

uint8_t *driver_prepare_response_ccid() {
    ccid_response = (struct ccid_header *)usb_get_tx(ITF_CCID);
    return &ccid_response->apdu;
}
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
