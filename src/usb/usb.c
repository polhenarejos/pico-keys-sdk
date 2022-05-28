
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

#define DEBUG_PAYLOAD(p,s) { \
    printf("Payload %s (%d bytes):\r\n", #p,s);\
    for (int i = 0; i < s; i += 16) {\
        printf("%07Xh : ",(unsigned int)(i+p));\
        for (int j = 0; j < 16; j++) {\
            if (j < s-i) printf("%02X ",(p)[i+j]);\
            else printf("   ");\
            if (j == 7) printf(" ");\
            } printf(":  "); \
        for (int j = 0; j < MIN(16,s-i); j++) {\
            printf("%c",(p)[i+j] == 0x0a || (p)[i+j] == 0x0d ? '\\' : (p)[i+j]);\
            if (j == 7) printf(" ");\
            }\
            printf("\r\n");\
        } printf("\r\n"); \
    }
    

uint32_t usb_write_flush() {
    if (w_len > 0 && tud_vendor_write_available() > 0) {
        printf("w_len %d %d %ld\r\n",w_len,tx_r_offset,tud_vendor_write_available());
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

struct ccid_class_descriptor {
	uint8_t  bLength;
	uint8_t  bDescriptorType;
	uint16_t bcdCCID;
	uint8_t  bMaxSlotIndex;
	uint8_t  bVoltageSupport;
	uint32_t dwProtocols;
	uint32_t dwDefaultClock;
	uint32_t dwMaximumClock;
	uint8_t  bNumClockSupport;
	uint32_t dwDataRate;
	uint32_t dwMaxDataRate;
	uint8_t  bNumDataRatesSupported;
	uint32_t dwMaxIFSD;
	uint32_t dwSynchProtocols;
	uint32_t dwMechanical;
	uint32_t dwFeatures;
	uint32_t dwMaxCCIDMessageLength;
	uint8_t  bClassGetResponse;
	uint8_t  bclassEnvelope;
	uint16_t wLcdLayout;
	uint8_t  bPINSupport;
	uint8_t  bMaxCCIDBusySlots;
} __attribute__ ((__packed__));

static const struct ccid_class_descriptor desc_ccid = {
    .bLength                = sizeof(struct ccid_class_descriptor),
    .bDescriptorType        = 0x21,
    .bcdCCID                = (0x0110),
    .bMaxSlotIndex          = 0,
    .bVoltageSupport        = 0x01,  // 5.0V
    .dwProtocols            = (
                              0x01|  // T=0
                              0x02), // T=1
    .dwDefaultClock         = (0xDFC),
    .dwMaximumClock         = (0xDFC),
    .bNumClockSupport       = 0,
    .dwDataRate             = (0x2580),
    .dwMaxDataRate          = (0x2580),
    .bNumDataRatesSupported = 0,
    .dwMaxIFSD              = (0xFE), // IFSD is handled by the real reader driver
    .dwSynchProtocols       = (0),
    .dwMechanical           = (0),
    .dwFeatures             = 0x40840, //USB-ICC, short & extended APDU
    .dwMaxCCIDMessageLength = 65544+10,
    .bClassGetResponse      = 0xFF,
    .bclassEnvelope         = 0xFF,
    .wLcdLayout             = 0x0,
    .bPINSupport            = 0x0,
    .bMaxCCIDBusySlots      = 0x01,
};

//--------------------------------------------------------------------+
// Device Descriptors
//--------------------------------------------------------------------+
tusb_desc_device_t const desc_device =
{
    .bLength            = sizeof(tusb_desc_device_t),
    .bDescriptorType    = TUSB_DESC_DEVICE,
    .bcdUSB             = (USB_BCD),

    .bDeviceClass       = 0x00,
    .bDeviceSubClass    = 0,
    .bDeviceProtocol    = 0,
    .bMaxPacketSize0    = CFG_TUD_ENDPOINT0_SIZE,

    .idVendor           = (USB_VID),
    .idProduct          = (USB_PID),
    .bcdDevice          = CCID_VERSION,

    .iManufacturer      = 1,
    .iProduct           = 2,
    .iSerialNumber      = 3,

    .bNumConfigurations = 1
};

uint8_t const * tud_descriptor_device_cb(void)
{
    return (uint8_t const *) &desc_device;
}

tusb_desc_interface_t const desc_interface = 
{
    .bLength            = sizeof(tusb_desc_interface_t),
    .bDescriptorType    = TUSB_DESC_INTERFACE,
    .bInterfaceNumber   = 0,
    .bAlternateSetting  = 0,
    .bNumEndpoints      = 2,
    .bInterfaceClass    = TUSB_CLASS_SMART_CARD,
    .bInterfaceSubClass = 0,
    .bInterfaceProtocol = 0,
    .iInterface         = 5,
};

//--------------------------------------------------------------------+
// Configuration Descriptor
//--------------------------------------------------------------------+

tusb_desc_configuration_t const desc_config  = 
{
    .bLength             = sizeof(tusb_desc_configuration_t),
  	.bDescriptorType     = TUSB_DESC_CONFIGURATION,
    .wTotalLength        = (sizeof(tusb_desc_configuration_t) + sizeof(tusb_desc_interface_t) + sizeof(struct ccid_class_descriptor) + 2*sizeof(tusb_desc_endpoint_t)),
  	.bNumInterfaces      = 1,
  	.bConfigurationValue = 1,
  	.iConfiguration      = 4,
  	.bmAttributes        = USB_CONFIG_ATT_ONE | TUSB_DESC_CONFIG_ATT_REMOTE_WAKEUP,
  	.bMaxPower           = TUSB_DESC_CONFIG_POWER_MA(MAX_USB_POWER+1),
};

tusb_desc_endpoint_t const desc_ep1 = 
{
    .bLength             = sizeof(tusb_desc_endpoint_t),
	.bDescriptorType     = TUSB_DESC_ENDPOINT,
	.bEndpointAddress    = TUSB_DIR_IN_MASK | 1,
	.bmAttributes.xfer   = TUSB_XFER_BULK,
	.wMaxPacketSize.size = (64),
	.bInterval           = 0
};

tusb_desc_endpoint_t const desc_ep2 = 
{
    .bLength             = sizeof(tusb_desc_endpoint_t),
	.bDescriptorType     = TUSB_DESC_ENDPOINT,
	.bEndpointAddress    = 2,
	.bmAttributes.xfer   = TUSB_XFER_BULK,
	.wMaxPacketSize.size = (64),
	.bInterval           = 0
};

static uint8_t desc_config_extended[sizeof(tusb_desc_configuration_t) + sizeof(tusb_desc_interface_t) + sizeof(struct ccid_class_descriptor) + 2*sizeof(tusb_desc_endpoint_t)];

uint8_t const * tud_descriptor_configuration_cb(uint8_t index)
{
    (void) index; // for multiple configurations
  
    static uint8_t initd = 0;
    if (initd == 0)
    {
        uint8_t *p = desc_config_extended;
        memcpy(p, &desc_config, sizeof(tusb_desc_configuration_t)); p += sizeof(tusb_desc_configuration_t);
        memcpy(p, &desc_interface, sizeof(tusb_desc_interface_t)); p += sizeof(tusb_desc_interface_t);
        memcpy(p, &desc_ccid, sizeof(struct ccid_class_descriptor)); p += sizeof(struct ccid_class_descriptor);
        memcpy(p, &desc_ep1, sizeof(tusb_desc_endpoint_t)); p += sizeof(tusb_desc_endpoint_t);
        memcpy(p, &desc_ep2, sizeof(tusb_desc_endpoint_t)); p += sizeof(tusb_desc_endpoint_t);
        initd = 1;
    }
    return (const uint8_t *)desc_config_extended;
}

//--------------------------------------------------------------------+
// String Descriptors
//--------------------------------------------------------------------+

// array of pointer to string descriptors
char const* string_desc_arr [] =
{
    (const char[]) { 0x09, 0x04 }, // 0: is supported language is English (0x0409)
    "Pol Henarejos",                     // 1: Manufacturer
    "Pico HSM",                       // 2: Product
    "11223344",                      // 3: Serials, should use chip ID
    "Pico HSM Config",               // 4: Vendor Interface
    "Pico HSM Interface"
};

static uint16_t _desc_str[32];

uint16_t const* tud_descriptor_string_cb(uint8_t index, uint16_t langid)
{
    (void) langid;

    uint8_t chr_count;

    if (index == 0) {
        memcpy(&_desc_str[1], string_desc_arr[0], 2);
        chr_count = 1;
    }
    else  {
        // Note: the 0xEE index string is a Microsoft OS 1.0 Descriptors.
        // https://docs.microsoft.com/en-us/windows-hardware/drivers/usbcon/microsoft-defined-usb-descriptors

        if ( !(index < sizeof(string_desc_arr)/sizeof(string_desc_arr[0])) ) 
            return NULL;

        const char* str = string_desc_arr[index];
        char unique_id_str[2 * PICO_UNIQUE_BOARD_ID_SIZE_BYTES + 1];
        if (index == 3) {
            pico_unique_board_id_t unique_id;
            pico_get_unique_board_id(&unique_id);
            pico_get_unique_board_id_string(unique_id_str, 2 * PICO_UNIQUE_BOARD_ID_SIZE_BYTES + 1);
            str = unique_id_str;
        }

        chr_count = strlen(str);
        if ( chr_count > 31 ) 
            chr_count = 31;

        // Convert ASCII string into UTF-16
        for(uint8_t i=0; i<chr_count; i++) {
            _desc_str[1+i] = str[i];
        }
    }

    _desc_str[0] = (TUSB_DESC_STRING << 8 ) | (2*chr_count + 2);

    return _desc_str;
}

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
