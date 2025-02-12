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

#include "tusb.h"
#include "usb_descriptors.h"
#if !defined(ENABLE_EMULATION) && !defined(ESP_PLATFORM)
#include "pico/unique_id.h"
#endif
#ifdef ESP_PLATFORM
#include "tinyusb.h"
#endif
#include "pico_keys_version.h"
#include "usb.h"
#include "pico_keys.h"

#ifndef USB_VID
#define USB_VID   0xFEFF
#endif
#ifndef USB_PID
#define USB_PID   0xFCFD
#endif

#define USB_BCD   0x0200

#define USB_CONFIG_ATT_ONE TU_BIT(7)

#define MAX_USB_POWER       2

//--------------------------------------------------------------------+
// Device Descriptors
//--------------------------------------------------------------------+
tusb_desc_device_t desc_device = {
    .bLength            = sizeof(tusb_desc_device_t),
    .bDescriptorType    = TUSB_DESC_DEVICE,
    .bcdUSB             = (USB_BCD),

    .bDeviceClass       = 0x00,
    .bDeviceSubClass    = 0,
    .bDeviceProtocol    = 0,
    .bMaxPacketSize0    = CFG_TUD_ENDPOINT0_SIZE,

    .idVendor           = (USB_VID),
    .idProduct          = (USB_PID),
    .bcdDevice          = PICO_KEYS_SDK_VERSION,

    .iManufacturer      = 1,
    .iProduct           = 2,
    .iSerialNumber      = 3,

    .bNumConfigurations = 1
};

#ifndef ESP_PLATFORM
uint8_t const *tud_descriptor_device_cb(void) {
    return (uint8_t const *) &desc_device;
}
#endif
//--------------------------------------------------------------------+
// Configuration Descriptor
//--------------------------------------------------------------------+

#define TUD_INTERFACE_DESC_LEN 9
#define TUD_ENDPOINT_DESC_LEN 7
#define TUSB_SMARTCARD_LEN 54
#define TUSB_WSMARTCARD_LEN 53

#define TUSB_SMARTCARD_CCID_DESC_LEN (TUD_INTERFACE_DESC_LEN + TUSB_SMARTCARD_LEN + TUSB_SMARTCARD_CCID_EPS * TUD_ENDPOINT_DESC_LEN)
#define TUSB_SMARTCARD_WCID_DESC_LEN (TUD_INTERFACE_DESC_LEN + TUSB_WSMARTCARD_LEN + 2 * TUD_ENDPOINT_DESC_LEN)

enum {
 TUSB_DESC_TOTAL_LEN = TUD_CONFIG_DESC_LEN
#ifdef USB_ITF_HID
        + TUD_HID_INOUT_DESC_LEN
        + TUD_HID_DESC_LEN
#endif
#ifdef USB_ITF_CCID
        + TUSB_SMARTCARD_CCID_DESC_LEN
        + TUSB_SMARTCARD_WCID_DESC_LEN
#endif
};

#ifdef USB_ITF_HID
uint8_t const desc_hid_report[] = {
    TUD_HID_REPORT_DESC_FIDO_U2F(CFG_TUD_HID_EP_BUFSIZE)
};
uint8_t const desc_hid_report_kb[] = {
    TUD_HID_REPORT_DESC_KEYBOARD(HID_USAGE_PAGE(HID_USAGE_DESKTOP_KEYBOARD), HID_USAGE_MIN(0), HID_USAGE_MAX_N(255,2), HID_LOGICAL_MIN(0), HID_LOGICAL_MAX_N(255, 2), HID_REPORT_COUNT(8), HID_REPORT_SIZE(8), HID_FEATURE( HID_DATA | HID_VARIABLE | HID_ABSOLUTE),)
};
#define EPNUM_HID   0x04
#endif

#ifdef USB_ITF_CCID
#define TUD_SMARTCARD_DESCRIPTOR_WEB(_itf, _strix, _epout, _epin, _epsize) \
    9, TUSB_DESC_INTERFACE, _itf, 0, 2, 0xFF, 0, 0, _strix, \
    TUSB_WSMARTCARD_LEN, 0x21, U16_TO_U8S_LE(0x0110), 0, 0x1, U32_TO_U8S_LE(0x01|0x2), U32_TO_U8S_LE(0xDFC), U32_TO_U8S_LE(0xDFC), 0, U32_TO_U8S_LE(0x2580), U32_TO_U8S_LE(0x2580), 0, U32_TO_U8S_LE(0xFE), U32_TO_U8S_LE(0), U32_TO_U8S_LE(0), U32_TO_U8S_LE(0x40840), U32_TO_U8S_LE(USB_BUFFER_SIZE), 0xFF, 0xFF, U16_TO_U8S_LE(0x0), 0, \
    7, TUSB_DESC_ENDPOINT, _epout, TUSB_XFER_BULK, U16_TO_U8S_LE(_epsize), 0, \
    7, TUSB_DESC_ENDPOINT, _epin,  TUSB_XFER_BULK, U16_TO_U8S_LE(_epsize), 0
#define TUD_SMARTCARD_DESCRIPTOR_2EP(_itf, _strix, _epout, _epin, _epsize) \
    9, TUSB_DESC_INTERFACE, _itf, 0, TUSB_SMARTCARD_CCID_EPS, TUSB_CLASS_SMART_CARD, 0, 0, _strix, \
    TUSB_SMARTCARD_LEN, 0x21, U16_TO_U8S_LE(0x0110), 0, 0x1, U32_TO_U8S_LE(0x01|0x2), U32_TO_U8S_LE(0xDFC), U32_TO_U8S_LE(0xDFC), 0, U32_TO_U8S_LE(0x2580), U32_TO_U8S_LE(0x2580), 0, U32_TO_U8S_LE(0xFE), U32_TO_U8S_LE(0), U32_TO_U8S_LE(0), U32_TO_U8S_LE(0x40840), U32_TO_U8S_LE(USB_BUFFER_SIZE), 0xFF, 0xFF, U16_TO_U8S_LE(0x0), 0, 0x1, \
    7, TUSB_DESC_ENDPOINT, _epout, TUSB_XFER_BULK, U16_TO_U8S_LE(_epsize), 0, \
    7, TUSB_DESC_ENDPOINT, _epin,  TUSB_XFER_BULK, U16_TO_U8S_LE(_epsize), 0
#if TUSB_SMARTCARD_CCID_EPS == 3
#define TUD_SMARTCARD_DESCRIPTOR(_itf, _strix, _epout, _epin, _epint, _epsize) \
    TUD_SMARTCARD_DESCRIPTOR_2EP(_itf, _strix, _epout, _epin, _epsize), \
    7, TUSB_DESC_ENDPOINT, _epint,  TUSB_XFER_INTERRUPT, U16_TO_U8S_LE(_epsize), 0
#else
#define TUD_SMARTCARD_DESCRIPTOR(_itf, _strix, _epout, _epin, _epint, _epsize) \
    TUD_SMARTCARD_DESCRIPTOR_2EP(_itf, _strix, _epout, _epin, _epsize)
#endif
#endif

const uint8_t desc_config[] = {
    TUD_CONFIG_DESCRIPTOR(1, ITF_TOTAL, 4, TUSB_DESC_TOTAL_LEN, USB_CONFIG_ATT_ONE | TUSB_DESC_CONFIG_ATT_REMOTE_WAKEUP, MAX_USB_POWER),
#ifdef USB_ITF_HID
    TUD_HID_INOUT_DESCRIPTOR(ITF_HID, ITF_HID + 5, HID_ITF_PROTOCOL_NONE, sizeof(desc_hid_report), EPNUM_HID, TUSB_DIR_IN_MASK | EPNUM_HID, CFG_TUD_HID_EP_BUFSIZE, 10),
    TUD_HID_DESCRIPTOR(ITF_KEYBOARD, ITF_KEYBOARD + 5, HID_ITF_PROTOCOL_NONE, sizeof(desc_hid_report_kb), TUSB_DIR_IN_MASK | (EPNUM_HID + 1), 16, 5),
#endif
#ifdef USB_ITF_CCID
    TUD_SMARTCARD_DESCRIPTOR(ITF_CCID, ITF_CCID+5, 1, TUSB_DIR_IN_MASK | 1, TUSB_DIR_IN_MASK | 2, 64),
    TUD_SMARTCARD_DESCRIPTOR_WEB(ITF_WCID, ITF_WCID+5, 3, TUSB_DIR_IN_MASK | 3, 64),
#endif
};

#ifdef USB_ITF_HID
uint8_t const *tud_hid_descriptor_report_cb(uint8_t itf) {
    printf("report_cb %d\n", itf);
    if (itf == ITF_HID_CTAP) {
        return desc_hid_report;
    }
    else if (itf == ITF_HID_KB) {
        return desc_hid_report_kb;
    }
    return NULL;
}
#endif
#ifndef ESP_PLATFORM
uint8_t const *tud_descriptor_configuration_cb(uint8_t index) {
    (void) index; // for multiple configurations
    return desc_config;
}
#endif

#define BOS_TOTAL_LEN     (TUD_BOS_DESC_LEN + TUD_BOS_WEBUSB_DESC_LEN + TUD_BOS_MICROSOFT_OS_DESC_LEN)
#define MS_OS_20_DESC_LEN  0xB2

enum
{
  VENDOR_REQUEST_WEBUSB = 1,
  VENDOR_REQUEST_MICROSOFT = 2
};
#define URL  "www.picokeys.com"
static bool web_serial_connected = false;

const tusb_desc_webusb_url_t desc_url =
{
  .bLength         = 3 + sizeof(URL) - 1,
  .bDescriptorType = 3, // WEBUSB URL type
  .bScheme         = 1, // 0: http, 1: https
  .url             = URL
};
#define BOS_TOTAL_LEN      (TUD_BOS_DESC_LEN + TUD_BOS_WEBUSB_DESC_LEN + TUD_BOS_MICROSOFT_OS_DESC_LEN)

#define MS_OS_20_DESC_LEN  0xB2
uint8_t const desc_ms_os_20[] = {
  // Set header: length, type, windows version, total length
  U16_TO_U8S_LE(0x000A), U16_TO_U8S_LE(MS_OS_20_SET_HEADER_DESCRIPTOR), U32_TO_U8S_LE(0x06030000), U16_TO_U8S_LE(MS_OS_20_DESC_LEN),

  // Configuration subset header: length, type, configuration index, reserved, configuration total length
  U16_TO_U8S_LE(0x0008), U16_TO_U8S_LE(MS_OS_20_SUBSET_HEADER_CONFIGURATION), 0, 0, U16_TO_U8S_LE(MS_OS_20_DESC_LEN-0x0A),

  // Function Subset header: length, type, first interface, reserved, subset length
  U16_TO_U8S_LE(0x0008), U16_TO_U8S_LE(MS_OS_20_SUBSET_HEADER_FUNCTION), ITF_WCID, 0, U16_TO_U8S_LE(MS_OS_20_DESC_LEN-0x0A-0x08),

  // MS OS 2.0 Compatible ID descriptor: length, type, compatible ID, sub compatible ID
  U16_TO_U8S_LE(0x0014), U16_TO_U8S_LE(MS_OS_20_FEATURE_COMPATBLE_ID), 'W', 'I', 'N', 'U', 'S', 'B', 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sub-compatible

  // MS OS 2.0 Registry property descriptor: length, type
  U16_TO_U8S_LE(MS_OS_20_DESC_LEN-0x0A-0x08-0x08-0x14), U16_TO_U8S_LE(MS_OS_20_FEATURE_REG_PROPERTY),
  U16_TO_U8S_LE(0x0007), U16_TO_U8S_LE(0x002A), // wPropertyDataType, wPropertyNameLength and PropertyName "DeviceInterfaceGUIDs\0" in UTF-16
  'D', 0x00, 'e', 0x00, 'v', 0x00, 'i', 0x00, 'c', 0x00, 'e', 0x00, 'I', 0x00, 'n', 0x00, 't', 0x00, 'e', 0x00,
  'r', 0x00, 'f', 0x00, 'a', 0x00, 'c', 0x00, 'e', 0x00, 'G', 0x00, 'U', 0x00, 'I', 0x00, 'D', 0x00, 's', 0x00, 0x00, 0x00,
  U16_TO_U8S_LE(0x0050), // wPropertyDataLength
	//bPropertyData: “{975F44D9-0D08-43FD-8B3E-127CA8AFFF9D}”.
  '{', 0x00, '9', 0x00, '7', 0x00, '5', 0x00, 'F', 0x00, '4', 0x00, '4', 0x00, 'D', 0x00, '9', 0x00, '-', 0x00,
  '0', 0x00, 'D', 0x00, '0', 0x00, '8', 0x00, '-', 0x00, '4', 0x00, '3', 0x00, 'F', 0x00, 'D', 0x00, '-', 0x00,
  '8', 0x00, 'B', 0x00, '3', 0x00, 'E', 0x00, '-', 0x00, '1', 0x00, '2', 0x00, '7', 0x00, 'C', 0x00, 'A', 0x00,
  '8', 0x00, 'A', 0x00, 'F', 0x00, 'F', 0x00, 'F', 0x00, '9', 0x00, 'D', 0x00, '}', 0x00, 0x00, 0x00, 0x00, 0x00
};
bool tud_vendor_control_xfer_cb(uint8_t rhport, uint8_t stage, tusb_control_request_t const * request) {
    // nothing to with DATA & ACK stage
    if (stage != CONTROL_STAGE_SETUP)
        return true;

    switch (request->bmRequestType_bit.type) {
        case TUSB_REQ_TYPE_VENDOR:
            switch (request->bRequest) {
                case VENDOR_REQUEST_WEBUSB:
                    return tud_control_xfer(rhport, request, (void*)(uintptr_t) &desc_url, desc_url.bLength);

                case VENDOR_REQUEST_MICROSOFT:
                    if (request->wIndex == 7) {
                        // Get Microsoft OS 2.0 compatible descriptor
                        uint16_t total_len;
                        memcpy(&total_len, desc_ms_os_20+8, 2);
                        return tud_control_xfer(rhport, request, (void*)(uintptr_t) desc_ms_os_20, total_len);
                    }
                    else {
                        return false;
                    }
                default:
                    break;
            }
            break;

        case TUSB_REQ_TYPE_CLASS:
            if (request->bRequest == 0x22) {
                web_serial_connected = (request->wValue != 0);
                if (web_serial_connected) {
                    printf("\nWebUSB interface connected\n");
                }
                return tud_control_status(rhport, request);
            }
            break;
        default:
            break;
  }
  // stall unknown request
  return false;
}

uint8_t const desc_bos[] = {
    // total length, number of device caps
    TUD_BOS_DESCRIPTOR(BOS_TOTAL_LEN, 2),
    // Vendor Code, iLandingPage
    TUD_BOS_WEBUSB_DESCRIPTOR(VENDOR_REQUEST_WEBUSB, 1),
    // Microsoft OS 2.0 descriptor
    TUD_BOS_MS_OS_20_DESCRIPTOR(MS_OS_20_DESC_LEN, VENDOR_REQUEST_MICROSOFT)
};

uint8_t const *tud_descriptor_bos_cb(void) {
    return desc_bos;
}

//--------------------------------------------------------------------+
// String Descriptors
//--------------------------------------------------------------------+

// array of pointer to string descriptors
char const *string_desc_arr [] = {
    (const char[]) { 0x09, 0x04 }, // 0: is supported language is English (0x0409)
    "Pol Henarejos",                     // 1: Manufacturer
    "Pico Key",                       // 2: Product
    "11223344",                      // 3: Serials, should use chip ID
    "Config"               // 4: Vendor Interface
#ifdef USB_ITF_HID
    , "HID Interface"
    , "HID Keyboard Interface"
#endif
#ifdef USB_ITF_CCID
    , "CCID OTP FIDO Interface"
    , "WebCCID Interface"
#endif
};

#ifdef ESP_PLATFORM
tinyusb_config_t tusb_cfg = {
    .device_descriptor = &desc_device,
    .string_descriptor = string_desc_arr,
    .string_descriptor_count = (sizeof(string_desc_arr) / sizeof(string_desc_arr[0])) > 8 ? 8 : (sizeof(string_desc_arr) / sizeof(string_desc_arr[0])),
    .external_phy = false,
    .configuration_descriptor = desc_config,
};
#else
static uint16_t _desc_str[32];

uint16_t const *tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
    (void) langid;

    uint8_t chr_count = 0;

    if (index == 0) {
        memcpy(&_desc_str[1], string_desc_arr[0], 2);
        chr_count = 1;
    }
    else {
        // Note: the 0xEE index string is a Microsoft OS 1.0 Descriptors.
        // https://docs.microsoft.com/en-us/windows-hardware/drivers/usbcon/microsoft-defined-usb-descriptors

        if (!(index < sizeof(string_desc_arr) / sizeof(string_desc_arr[0]))) {
            return NULL;
        }

        const char *str = string_desc_arr[index];
        if (index == 3) {
            str = pico_serial_str;
        }
        else if (index == 2) {
            if (phy_data.usb_product_present) {
                str = phy_data.usb_product;
            }
        }

        uint8_t buff_avail = sizeof(_desc_str) / sizeof(_desc_str[0]) - 1;
        if (index >= 4) {
            const char *product = phy_data.usb_product_present ? phy_data.usb_product : string_desc_arr[2];
            uint8_t len = MIN(strlen(product), buff_avail);
            for (int ix = 0; ix < len; chr_count++, ix++) {
                _desc_str[1 + chr_count] = product[ix];
            }
            buff_avail -= len;
            if (buff_avail > 0) {
                _desc_str[1 + chr_count++] = ' ';
                buff_avail--;
            }
        }
        for (int ix = 0; ix < MIN(strlen(str), buff_avail); chr_count++, ix++) {
            _desc_str[1 + chr_count] = str[ix];
        }
    }

    _desc_str[0] = (TUSB_DESC_STRING << 8) | (2 * chr_count + 2);

    return _desc_str;
}
#endif
