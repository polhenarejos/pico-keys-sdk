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

#include "random.h"
#include "pico_keys.h"
#ifdef PICO_PLATFORM
#include "bsp/board.h"
#endif
#ifndef ENABLE_EMULATION
#include "tusb.h"
#include "device/usbd_pvt.h"
#else
#include "emulation.h"
#endif
#include "ccid.h"
#include "usb_descriptors.h"
#include "apdu.h"
#include "usb.h"

#if MAX_RES_APDU_DATA_SIZE > MAX_CMD_APDU_DATA_SIZE
#define USB_BUF_SIZE (MAX_RES_APDU_DATA_SIZE + 20 + 9)
#else
#define USB_BUF_SIZE (MAX_CMD_APDU_DATA_SIZE + 20 + 9)
#endif

#define CCID_SET_PARAMS         0x61 /* non-ICCD command  */
#define CCID_POWER_ON           0x62
#define CCID_POWER_OFF          0x63
#define CCID_SLOT_STATUS        0x65 /* non-ICCD command */
#define CCID_SECURE             0x69 /* non-ICCD command */
#define CCID_GET_PARAMS         0x6C /* non-ICCD command */
#define CCID_RESET_PARAMS       0x6D /* non-ICCD command */
#define CCID_XFR_BLOCK          0x6F
#define CCID_DATA_BLOCK_RET     0x80
#define CCID_SLOT_STATUS_RET    0x81 /* non-ICCD result */
#define CCID_PARAMS_RET         0x82 /* non-ICCD result */

#define CCID_MSG_SEQ_OFFSET     6
#define CCID_MSG_STATUS_OFFSET  7
#define CCID_MSG_ERROR_OFFSET   8
#define CCID_MSG_CHAIN_OFFSET   9
#define CCID_MSG_DATA_OFFSET    10  /* == CCID_MSG_HEADER_SIZE */
#define CCID_MAX_MSG_DATA_SIZE  USB_BUF_SIZE

#define CCID_STATUS_RUN     0x00
#define CCID_STATUS_PRESENT 0x01
#define CCID_STATUS_NOTPRESENT  0x02
#define CCID_CMD_STATUS_OK  0x00
#define CCID_CMD_STATUS_ERROR   0x40
#define CCID_CMD_STATUS_TIMEEXT 0x80

#define CCID_ERROR_XFR_OVERRUN  0xFC

/*
 * Since command-byte is at offset 0,
 * error with offset 0 means "command not supported".
 */
#define CCID_OFFSET_CMD_NOT_SUPPORTED 0
#define CCID_OFFSET_DATA_LEN 1
#define CCID_OFFSET_PARAM 8

#define CCID_THREAD_TERMINATED 0xffff
#define CCID_ACK_TIMEOUT 0x6600

PACK(
typedef struct {
    uint8_t bMessageType;
    uint32_t dwLength;
    uint8_t bSlot;
    uint8_t bSeq;
    uint8_t abRFU0;
    uint16_t abRFU1;
    uint8_t apdu; //Actually it is an array
}) ccid_header_t;

uint8_t ccid_status = 1;
#ifndef ENABLE_EMULATION
static uint8_t itf_num;
#endif

static usb_buffer_t ccid_rx[ITF_SC_TOTAL] = {0}, ccid_tx[ITF_SC_TOTAL] = {0};

int driver_process_usb_packet_ccid(uint8_t itf, uint16_t rx_read);

void ccid_write_offset(uint8_t itf, uint16_t size, uint16_t offset) {
    ccid_tx[itf].w_ptr += size + offset;
    ccid_tx[itf].r_ptr += offset;
}

void ccid_write(uint8_t itf, uint16_t size) {
    ccid_write_offset(itf, size, 0);
}

ccid_header_t *ccid_response[ITF_SC_TOTAL];
ccid_header_t *ccid_resp_fast[ITF_SC_TOTAL];
ccid_header_t *ccid_header[ITF_SC_TOTAL];

uint8_t sc_itf_to_usb_itf(uint8_t itf) {
    if (itf == ITF_SC_CCID) {
        return ITF_CCID;
    }
    else if (itf == ITF_SC_WCID) {
        return ITF_WCID;
    }
    return itf;
}

int driver_init_ccid(uint8_t itf) {
    ccid_header[itf] = (ccid_header_t *) (ccid_rx[itf].buffer + ccid_rx[itf].r_ptr);
    ccid_resp_fast[itf] = (ccid_header_t *) (ccid_tx[itf].buffer + sizeof(ccid_tx[itf].buffer) - 64);
//    apdu.header = &ccid_header->apdu;

    ccid_response[itf] = (ccid_header_t *) (ccid_tx[itf].buffer + ccid_tx[itf].w_ptr);

    usb_set_timeout_counter(sc_itf_to_usb_itf(itf), 1500);

    //ccid_tx[itf].w_ptr = ccid_tx[itf].r_ptr = 0;

    return CCID_OK;
}

void tud_vendor_rx_cb(uint8_t itf) {
    uint32_t len = tud_vendor_n_available(itf);
    do {
        uint16_t tlen = 0;
        if (len > 0xFFFF) {
            tlen = 0xFFFF;
        }
        else {
            tlen = (uint16_t)len;
        }
        tlen = (uint16_t)tud_vendor_n_read(itf, ccid_rx[itf].buffer + ccid_rx[itf].w_ptr, tlen);
        ccid_rx[itf].w_ptr += tlen;
        driver_process_usb_packet_ccid(itf, tlen);
        len -= tlen;
    } while (len > 0);
}

void tud_vendor_tx_cb(uint8_t itf, uint32_t sent_bytes) {
    (void) sent_bytes;
    tud_vendor_n_write_flush(itf);
}

int driver_write_ccid(uint8_t itf, const uint8_t *tx_buffer, uint16_t buffer_size) {
    if (*tx_buffer != 0x81) {
        DEBUG_PAYLOAD(tx_buffer, buffer_size);
    }
    int r = tud_vendor_n_write(itf, tx_buffer, buffer_size);
    if (r > 0) {
        tud_vendor_n_flush(itf);

        ccid_tx[itf].r_ptr += (uint16_t)buffer_size;
        if (ccid_tx[itf].r_ptr >= ccid_tx[itf].w_ptr) {
            ccid_tx[itf].r_ptr = ccid_tx[itf].w_ptr = 0;
        }

    }
#ifdef ENABLE_EMULATION
    tud_vendor_tx_cb(itf, r);
#endif
    return r;
}

int ccid_write_fast(uint8_t itf, const uint8_t *buffer, uint16_t buffer_size) {
    return driver_write_ccid(itf, buffer, buffer_size);
}

int driver_process_usb_packet_ccid(uint8_t itf, uint16_t rx_read) {
    (void) rx_read;
    if (ccid_rx[itf].w_ptr - ccid_rx[itf].r_ptr >= 10) {
        driver_init_ccid(itf);
        //printf("ccid_process %ld %d %x %x %d\n",ccid_header[itf]->dwLength,rx_read-10,ccid_header[itf]->bMessageType,ccid_header[itf]->bSeq,ccid_rx[itf].w_ptr - ccid_rx[itf].r_ptr - 10);
        if (ccid_header[itf]->dwLength <= (uint32_t)(ccid_rx[itf].w_ptr - ccid_rx[itf].r_ptr - 10)){
            ccid_rx[itf].r_ptr += (uint16_t)(ccid_header[itf]->dwLength + 10);
            if (ccid_rx[itf].r_ptr >= ccid_rx[itf].w_ptr) {
                ccid_rx[itf].r_ptr = ccid_rx[itf].w_ptr = 0;
            }

            size_t apdu_sent = 0;
            if (ccid_header[itf]->bMessageType != CCID_SLOT_STATUS) {
                DEBUG_PAYLOAD((uint8_t *)ccid_header[itf], ccid_header[itf]->dwLength + 10);
            }
            if (ccid_header[itf]->bMessageType == CCID_SLOT_STATUS) {
                ccid_resp_fast[itf]->bMessageType = CCID_SLOT_STATUS_RET;
                ccid_resp_fast[itf]->dwLength = 0;
                ccid_resp_fast[itf]->bSlot = 0;
                ccid_resp_fast[itf]->bSeq = ccid_header[itf]->bSeq;
                ccid_resp_fast[itf]->abRFU0 = ccid_status;
                ccid_resp_fast[itf]->abRFU1 = 0;
                ccid_write_fast(itf, (const uint8_t *)ccid_resp_fast[itf], 10);
            }
            else if (ccid_header[itf]->bMessageType == CCID_POWER_ON) {
                size_t size_atr = (ccid_atr ? ccid_atr[0] : 0);
                ccid_resp_fast[itf]->bMessageType = CCID_DATA_BLOCK_RET;
                ccid_resp_fast[itf]->dwLength = (uint32_t)size_atr;
                ccid_resp_fast[itf]->bSlot = 0;
                ccid_resp_fast[itf]->bSeq = ccid_header[itf]->bSeq;
                ccid_resp_fast[itf]->abRFU0 = 0;
                ccid_resp_fast[itf]->abRFU1 = 0;
                //printf("1 %x %x %x || %x %x %x\n",ccid_resp_fast->apdu,apdu.rdata,ccid_resp_fast,ccid_header,ccid_header->apdu,apdu.data);
                memcpy(&ccid_resp_fast[itf]->apdu, ccid_atr + 1, size_atr);
                if (ccid_status == 1) {
                    //card_start(apdu_thread);
                }
                ccid_status = 0;
                ccid_write_fast(itf, (const uint8_t *)ccid_resp_fast[itf], (uint16_t)(size_atr + 10));

                led_set_blink(BLINK_MOUNTED);
            }
            else if (ccid_header[itf]->bMessageType == CCID_POWER_OFF) {
                if (ccid_status == 0) {
                    //card_exit(0);
                }
                ccid_status = 1;
                ccid_resp_fast[itf]->bMessageType = CCID_SLOT_STATUS_RET;
                ccid_resp_fast[itf]->dwLength = 0;
                ccid_resp_fast[itf]->bSlot = 0;
                ccid_resp_fast[itf]->bSeq = ccid_header[itf]->bSeq;
                ccid_resp_fast[itf]->abRFU0 = ccid_status;
                ccid_resp_fast[itf]->abRFU1 = 0;
                ccid_write_fast(itf, (const uint8_t *)ccid_resp_fast[itf], 10);

                led_set_blink(BLINK_SUSPENDED);
            }
            else if (ccid_header[itf]->bMessageType == CCID_SET_PARAMS ||
                     ccid_header[itf]->bMessageType == CCID_GET_PARAMS ||
                     ccid_header[itf]->bMessageType == CCID_RESET_PARAMS) {
                /* Values from gnuk. Not specified in ICCD spec. */
                const uint8_t params[] =  {
                    0x11, /* bmFindexDindex */
                    0x10, /* bmTCCKST1 */
                    0xFE, /* bGuardTimeT1 */
                    0x55, /* bmWaitingIntegersT1 */
                    0x03, /* bClockStop */
                    0xFE, /* bIFSC */
                    0    /* bNadValue */
                };
                ccid_resp_fast[itf]->bMessageType = CCID_PARAMS_RET;
                ccid_resp_fast[itf]->dwLength = sizeof(params);
                ccid_resp_fast[itf]->bSlot = 0;
                ccid_resp_fast[itf]->bSeq = ccid_header[itf]->bSeq;
                ccid_resp_fast[itf]->abRFU0 = ccid_status;
                ccid_resp_fast[itf]->abRFU1 = 0x0100;
                memcpy(&ccid_resp_fast[itf]->apdu, params, sizeof(params));
                ccid_write_fast(itf, (const uint8_t *)ccid_resp_fast[itf], sizeof(params) + 10);
            }
            else if (ccid_header[itf]->bMessageType == CCID_XFR_BLOCK) {
                apdu.rdata = &ccid_response[itf]->apdu;
                apdu_sent = apdu_process(itf, &ccid_header[itf]->apdu, (uint16_t)ccid_header[itf]->dwLength);
#ifndef ENABLE_EMULATION
                if (apdu_sent > 0) {
                    card_start(sc_itf_to_usb_itf(itf), apdu_thread);
                    usb_send_event(EV_CMD_AVAILABLE);
                }
#endif
            }
            return (uint16_t)apdu_sent;
        }
    }
    return 0;
}

void driver_exec_timeout_ccid(uint8_t itf) {
    ccid_resp_fast[itf]->bMessageType = CCID_DATA_BLOCK_RET;
    ccid_resp_fast[itf]->dwLength = 0;
    ccid_resp_fast[itf]->bSlot = 0;
    ccid_resp_fast[itf]->bSeq = ccid_header[itf]->bSeq;
    ccid_resp_fast[itf]->abRFU0 = CCID_CMD_STATUS_TIMEEXT;
    ccid_resp_fast[itf]->abRFU1 = 0;
    ccid_write_fast(itf, (const uint8_t *)ccid_resp_fast[itf], 10);
}

void driver_exec_finished_ccid(uint8_t itf, uint16_t size_next) {
    driver_exec_finished_cont_ccid(itf, size_next, 0);
}

void driver_exec_finished_cont_ccid(uint8_t itf, uint16_t size_next, uint16_t offset) {
    ccid_response[itf] = (ccid_header_t *) (ccid_tx[itf].buffer + ccid_tx[itf].w_ptr + offset);
    ccid_response[itf]->bMessageType = CCID_DATA_BLOCK_RET;
    ccid_response[itf]->dwLength = size_next;
    ccid_response[itf]->bSlot = 0;
    ccid_response[itf]->bSeq = ccid_header[itf]->bSeq;
    ccid_response[itf]->abRFU0 = ccid_status;
    ccid_response[itf]->abRFU1 = 0;
    ccid_write_offset(itf, size_next+10, offset);
}

void ccid_task() {
    for (int itf = 0; itf < ITF_SC_TOTAL; itf++) {
        int status = card_status(sc_itf_to_usb_itf(itf));
        if (status == CCID_OK) {
            driver_exec_finished_ccid(itf, finished_data_size);
        }
        else if (status == CCID_ERR_BLOCKED) {
            driver_exec_timeout_ccid(itf);
        }
        if (ccid_tx[itf].w_ptr > ccid_tx[itf].r_ptr) {
            if (driver_write_ccid(itf, ccid_tx[itf].buffer + ccid_tx[itf].r_ptr, ccid_tx[itf].w_ptr - ccid_tx[itf].r_ptr) > 0) {

            }
        }
    }
}

#ifndef ENABLE_EMULATION

#define USB_CONFIG_ATT_ONE TU_BIT(7)

#define MAX_USB_POWER       1

static void ccid_init_cb(void) {
    vendord_init();
}

static void ccid_reset_cb(uint8_t rhport) {
    itf_num = 0;
    vendord_reset(rhport);
}

static uint16_t ccid_open(uint8_t rhport, tusb_desc_interface_t const *itf_desc, uint16_t max_len) {
    uint8_t *itf_vendor = (uint8_t *) malloc(sizeof(uint8_t) * max_len);
    TU_VERIFY( itf_desc->bInterfaceClass == TUSB_CLASS_SMART_CARD && itf_desc->bInterfaceSubClass == 0 && itf_desc->bInterfaceProtocol == 0, 0);

    //vendord_open expects a CLASS_VENDOR interface class
    uint16_t const drv_len = sizeof(tusb_desc_interface_t) + sizeof(struct ccid_class_descriptor) + 3 * sizeof(tusb_desc_endpoint_t);
    memcpy(itf_vendor, itf_desc, sizeof(uint8_t) * max_len);
    ((tusb_desc_interface_t *) itf_vendor)->bInterfaceClass = TUSB_CLASS_VENDOR_SPECIFIC;
    ((tusb_desc_interface_t *) itf_vendor)->bNumEndpoints -= 1;
    vendord_open(rhport, (tusb_desc_interface_t *) itf_vendor, max_len - sizeof(tusb_desc_endpoint_t));
    tusb_desc_endpoint_t const *desc_ep = (tusb_desc_endpoint_t const *)((uint8_t *)itf_desc + drv_len - sizeof(tusb_desc_endpoint_t));
    TU_ASSERT(usbd_edpt_open(rhport, desc_ep), 0);
    free(itf_vendor);

    uint8_t msg[] = { 0x50, 0x03 };
    usbd_edpt_xfer(rhport, desc_ep->bEndpointAddress, msg, sizeof(msg));

    TU_VERIFY(max_len >= drv_len, 0);

    itf_num = itf_desc->bInterfaceNumber;
    return drv_len;
}

// Support for parameterized reset via vendor interface control request
static bool ccid_control_xfer_cb(uint8_t __unused rhport,
                                 uint8_t stage,
                                 tusb_control_request_t const *request) {
    // nothing to do with DATA & ACK stage
    TU_LOG2("-------- CCID CTRL XFER\n");
    if (stage != CONTROL_STAGE_SETUP) {
        return true;
    }

    if (request->wIndex == itf_num) {
        TU_LOG2("-------- bmRequestType %x, bRequest %x, wValue %x, wLength %x\n",
                request->bmRequestType,
                request->bRequest,
                request->wValue,
                request->wLength);
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

static bool ccid_xfer_cb(uint8_t rhport,
                         uint8_t ep_addr,
                         xfer_result_t result,
                         uint32_t xferred_bytes) {
    //printf("------ CALLED XFER_CB\n");
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
#endif
