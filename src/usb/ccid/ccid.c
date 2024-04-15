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
#if !defined(ENABLE_EMULATION) && !defined(ESP_PLATFORM)
#include "hardware/rtc.h"
#endif
#include "tusb.h"
#include "ccid.h"
#include "device/usbd_pvt.h"
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

struct ccid_header {
    uint8_t bMessageType;
    uint32_t dwLength;
    uint8_t bSlot;
    uint8_t bSeq;
    uint8_t abRFU0;
    uint16_t abRFU1;
    uint8_t apdu; //Actually it is an array
} __attribute__((__packed__));

uint8_t ccid_status = 1;
static uint8_t itf_num;

void ccid_write_offset(uint8_t itf, uint16_t size, uint16_t offset) {
    if (*usb_get_tx(itf) + offset != 0x81) {
        DEBUG_PAYLOAD(usb_get_tx(itf) + offset, size + 10);
    }
    usb_write_offset(itf, size + 10, offset);
}

void ccid_write(uint8_t itf, uint16_t size) {
    ccid_write_offset(itf, size, 0);
}

struct ccid_header *ccid_response[ITF_TOTAL];
struct ccid_header *ccid_header[ITF_TOTAL];

int driver_init_ccid(uint8_t itf) {
    ccid_header[itf] = (struct ccid_header *) usb_get_rx(itf);
//    apdu.header = &ccid_header->apdu;

    ccid_response[itf] = (struct ccid_header *) usb_get_tx(itf);

    usb_set_timeout_counter(itf, 1500);

    return CCID_OK;
}

void tud_vendor_rx_cb(uint8_t itf) {
    uint32_t len = tud_vendor_n_available(itf);
    usb_rx(itf, NULL, len);
}

void tud_vendor_tx_cb(uint8_t itf, uint32_t sent_bytes) {
    //printf("written %ld\n", sent_bytes);
    usb_write_flush(itf);
}

int driver_write_ccid(uint8_t itf, const uint8_t *buffer, uint16_t buffer_size) {
    int r = tud_vendor_n_write(itf, buffer, buffer_size);
    if (r > 0) {
        return MAX(tud_vendor_n_flush(itf), r);
    }
    return r;
}

uint16_t driver_read_ccid(uint8_t itf, uint8_t *buffer, uint16_t buffer_size) {
    return tud_vendor_n_read(itf, buffer, buffer_size);
}

int driver_process_usb_nopacket_ccid() {
    return 0;
}

int driver_process_usb_packet_ccid(uint8_t itf, uint16_t rx_read) {
    if (rx_read >= 10) {
        driver_init_ccid(itf);
        //printf("%ld %d %x %x\n",ccid_header->dwLength,rx_read-10,ccid_header->bMessageType,ccid_header->bSeq);
        if (ccid_header[itf]->dwLength <= rx_read - 10) {
            size_t apdu_sent = 0;
            if (ccid_header[itf]->bMessageType != CCID_SLOT_STATUS) {
                DEBUG_PAYLOAD(usb_get_rx(itf), usb_read_available(itf));
            }
            if (ccid_header[itf]->bMessageType == CCID_SLOT_STATUS) {
                ccid_response[itf]->bMessageType = CCID_SLOT_STATUS_RET;
                ccid_response[itf]->dwLength = 0;
                ccid_response[itf]->bSlot = 0;
                ccid_response[itf]->bSeq = ccid_header[itf]->bSeq;
                ccid_response[itf]->abRFU0 = ccid_status;
                ccid_response[itf]->abRFU1 = 0;
                ccid_write(itf, 0);
            }
            else if (ccid_header[itf]->bMessageType == CCID_POWER_ON) {
                size_t size_atr = (ccid_atr ? ccid_atr[0] : 0);
                ccid_response[itf]->bMessageType = CCID_DATA_BLOCK_RET;
                ccid_response[itf]->dwLength = size_atr;
                ccid_response[itf]->bSlot = 0;
                ccid_response[itf]->bSeq = ccid_header[itf]->bSeq;
                ccid_response[itf]->abRFU0 = 0;
                ccid_response[itf]->abRFU1 = 0;
                //printf("1 %x %x %x || %x %x %x\n",ccid_response->apdu,apdu.rdata,ccid_response,ccid_header,ccid_header->apdu,apdu.data);
                memcpy(&ccid_response[itf]->apdu, ccid_atr + 1, size_atr);
                if (ccid_status == 1) {
                    card_start(apdu_thread);
                }
                ccid_status = 0;
                ccid_write(itf, size_atr);
            }
            else if (ccid_header[itf]->bMessageType == CCID_POWER_OFF) {
                if (ccid_status == 0) {
                    card_exit(0);
                }
                ccid_status = 1;
                ccid_response[itf]->bMessageType = CCID_SLOT_STATUS_RET;
                ccid_response[itf]->dwLength = 0;
                ccid_response[itf]->bSlot = 0;
                ccid_response[itf]->bSeq = ccid_header[itf]->bSeq;
                ccid_response[itf]->abRFU0 = ccid_status;
                ccid_response[itf]->abRFU1 = 0;
                ccid_write(itf, 0);
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
                ccid_response[itf]->bMessageType = CCID_PARAMS_RET;
                ccid_response[itf]->dwLength = sizeof(params);
                ccid_response[itf]->bSlot = 0;
                ccid_response[itf]->bSeq = ccid_header[itf]->bSeq;
                ccid_response[itf]->abRFU0 = ccid_status;
                ccid_response[itf]->abRFU1 = 0x0100;
                memcpy(&ccid_response[itf]->apdu, params, sizeof(params));
                ccid_write(itf, sizeof(params));
            }
            else if (ccid_header[itf]->bMessageType == CCID_XFR_BLOCK) {
                apdu_sent = apdu_process(itf, &ccid_header[itf]->apdu, ccid_header[itf]->dwLength);
            }
            usb_clear_rx(itf);
            return apdu_sent;
        }
    }
    return 0;
}

bool driver_mounted_ccid(uint8_t itf) {
    return tud_vendor_n_mounted(itf);
}

void driver_exec_timeout_ccid(uint8_t itf) {
    ccid_header[itf] = (struct ccid_header *) usb_get_rx(itf);
    ccid_response[itf] = (struct ccid_header *) (usb_get_tx(itf));
    ccid_response[itf]->bMessageType = CCID_DATA_BLOCK_RET;
    ccid_response[itf]->dwLength = 0;
    ccid_response[itf]->bSlot = 0;
    ccid_response[itf]->bSeq = ccid_header[itf]->bSeq;
    ccid_response[itf]->abRFU0 = CCID_CMD_STATUS_TIMEEXT;
    ccid_response[itf]->abRFU1 = 0;
    ccid_write(itf, 0);
}

void driver_exec_finished_ccid(uint8_t itf, uint16_t size_next) {
    ccid_header[itf] = (struct ccid_header *) usb_get_rx(itf);
    ccid_response[itf] = (struct ccid_header *) (usb_get_tx(itf) + 34);
    ccid_response[itf]->bMessageType = CCID_DATA_BLOCK_RET;
    ccid_response[itf]->dwLength = size_next;
    ccid_response[itf]->bSlot = 0;
    ccid_response[itf]->bSeq = ccid_header[itf]->bSeq;
    ccid_response[itf]->abRFU0 = ccid_status;
    ccid_response[itf]->abRFU1 = 0;
    ccid_write_offset(itf, size_next, 34);
}

void driver_exec_finished_cont_ccid(uint8_t itf, uint16_t size_next, uint16_t offset) {
    ccid_header[itf] = (struct ccid_header *) usb_get_rx(itf);
    ccid_response[itf] = (struct ccid_header *) (usb_get_tx(itf) + offset - 10 + 34);
    ccid_response[itf]->bMessageType = CCID_DATA_BLOCK_RET;
    ccid_response[itf]->dwLength = size_next;
    ccid_response[itf]->bSlot = 0;
    ccid_response[itf]->bSeq = ccid_header[itf]->bSeq;
    ccid_response[itf]->abRFU0 = ccid_status;
    ccid_response[itf]->abRFU1 = 0;
    ccid_write_offset(itf, size_next, offset - 10 + 34);
}

uint8_t *driver_prepare_response_ccid(uint8_t itf) {
    ccid_response[itf] = (struct ccid_header *) (usb_get_tx(itf) + 34);
    apdu.rdata = &ccid_response[itf]->apdu;
    apdu.rlen = 0;
    return &ccid_response[itf]->apdu;
}
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
