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
#include "pico/unique_id.h"
#include "pico_keys_version.h"
#include "usb.h"

#ifndef USB_VID
#define USB_VID   0xFEFF
#endif
#ifndef USB_PID
#define USB_PID   0xFCFD
#endif

#define USB_BCD   0x0200

#define USB_CONFIG_ATT_ONE TU_BIT(7)

#define MAX_USB_POWER       1


//--------------------------------------------------------------------+
// Device Descriptors
//--------------------------------------------------------------------+
tusb_desc_device_t const desc_device = {
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

uint8_t const *tud_descriptor_device_cb(void) {
    return (uint8_t const *) &desc_device;
}


//--------------------------------------------------------------------+
// Configuration Descriptor
//--------------------------------------------------------------------+

tusb_desc_configuration_t const desc_config  = {
    .bLength             = sizeof(tusb_desc_configuration_t),
    .bDescriptorType     = TUSB_DESC_CONFIGURATION,
    .wTotalLength        = (sizeof(tusb_desc_configuration_t)
#ifdef USB_ITF_CCID
                            + sizeof(tusb_desc_interface_t) + sizeof(struct ccid_class_descriptor) +
                            3 * sizeof(tusb_desc_endpoint_t)
#endif
#ifdef USB_ITF_HID
                            + TUD_HID_INOUT_DESC_LEN + TUD_HID_DESC_LEN
#endif
                            ),
    .bNumInterfaces      = ITF_TOTAL,
    .bConfigurationValue = 1,
    .iConfiguration      = 4,
    .bmAttributes        = USB_CONFIG_ATT_ONE | TUSB_DESC_CONFIG_ATT_REMOTE_WAKEUP,
    .bMaxPower           = TUSB_DESC_CONFIG_POWER_MA(MAX_USB_POWER + 1),
};

#ifdef USB_ITF_CCID
static const struct ccid_class_descriptor desc_ccid = {
    .bLength                = sizeof(struct ccid_class_descriptor),
    .bDescriptorType        = 0x21,
    .bcdCCID                = (0x0110),
    .bMaxSlotIndex          = 0,
    .bVoltageSupport        = 0x01,  // 5.0V
    .dwProtocols            = (
        0x01 |                        // T=0
        0x02),                       // T=1
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
    .dwMaxCCIDMessageLength = 65544 + 10,
    .bClassGetResponse      = 0xFF,
    .bclassEnvelope         = 0xFF,
    .wLcdLayout             = 0x0,
    .bPINSupport            = 0x0,
    .bMaxCCIDBusySlots      = 0x01,
};

tusb_desc_interface_t const desc_interface = {
    .bLength            = sizeof(tusb_desc_interface_t),
    .bDescriptorType    = TUSB_DESC_INTERFACE,
    .bInterfaceNumber   = ITF_CCID,
    .bAlternateSetting  = 0,
    .bNumEndpoints      = 3,
    .bInterfaceClass    = TUSB_CLASS_SMART_CARD,
    .bInterfaceSubClass = 0,
    .bInterfaceProtocol = 0,
    .iInterface         = ITF_CCID + 5,
};

tusb_desc_endpoint_t const desc_ep1 = {
    .bLength             = sizeof(tusb_desc_endpoint_t),
    .bDescriptorType     = TUSB_DESC_ENDPOINT,
    .bEndpointAddress    = TUSB_DIR_IN_MASK | 1,
    .bmAttributes.xfer   = TUSB_XFER_BULK,
    .wMaxPacketSize = (64),
    .bInterval           = 0
};

tusb_desc_endpoint_t const desc_ep2 = {
    .bLength             = sizeof(tusb_desc_endpoint_t),
    .bDescriptorType     = TUSB_DESC_ENDPOINT,
    .bEndpointAddress    = 1,
    .bmAttributes.xfer   = TUSB_XFER_BULK,
    .wMaxPacketSize = (64),
    .bInterval           = 0
};

tusb_desc_endpoint_t const desc_ep3 = {
    .bLength             = sizeof(tusb_desc_endpoint_t),
    .bDescriptorType     = TUSB_DESC_ENDPOINT,
    .bEndpointAddress    = TUSB_DIR_IN_MASK | 2,
    .bmAttributes.xfer   = TUSB_XFER_INTERRUPT,
    .wMaxPacketSize = (64),
    .bInterval           = 0
};
#endif

static uint8_t desc_config_extended[sizeof(tusb_desc_configuration_t)
#ifdef USB_ITF_CCID
                                    + sizeof(tusb_desc_interface_t) +
                                    sizeof(struct ccid_class_descriptor) + 3 *
                                    sizeof(tusb_desc_endpoint_t)
#endif
#ifdef USB_ITF_HID
                                    + TUD_HID_INOUT_DESC_LEN + TUD_HID_DESC_LEN
#endif
];

#ifdef USB_ITF_HID
uint8_t const desc_hid_report[] = {
    TUD_HID_REPORT_DESC_FIDO_U2F(CFG_TUD_HID_EP_BUFSIZE)
};
uint8_t const desc_hid_report_kb[] = {
    TUD_HID_REPORT_DESC_KEYBOARD(HID_USAGE(HID_USAGE_DESKTOP_GAMEPAD), HID_LOGICAL_MIN(0), HID_LOGICAL_MAX_N(255, 2), HID_REPORT_COUNT(8), HID_REPORT_SIZE(8), HID_FEATURE( HID_DATA | HID_VARIABLE | HID_ABSOLUTE), )
};
#define EPNUM_HID   0x03

static uint8_t desc_hid[] = {
    TUD_HID_INOUT_DESCRIPTOR(ITF_HID,
                             ITF_HID + 5,
                             HID_ITF_PROTOCOL_NONE,
                             sizeof(desc_hid_report),
                             EPNUM_HID,
                             0x80 | EPNUM_HID,
                             CFG_TUD_HID_EP_BUFSIZE,
                             10)
};

static uint8_t desc_hid_kb[] = {
    TUD_HID_DESCRIPTOR(ITF_KEYBOARD, ITF_KEYBOARD + 5, HID_ITF_PROTOCOL_NONE,
                       sizeof(desc_hid_report_kb), 0x80 | (EPNUM_HID + 1), 16, 5)
};
#include "apdu.h"
uint8_t const *tud_hid_descriptor_report_cb(uint8_t itf) {
    printf("report_cb %d\n", itf);
    DEBUG_DATA(desc_hid_report, sizeof(desc_hid_report));
    if (itf == ITF_HID) {
        return desc_hid_report;
    }
    else if (itf == ITF_KEYBOARD) {
        return desc_hid_report_kb;
    }
    return NULL;
}
#endif

uint8_t const *tud_descriptor_configuration_cb(uint8_t index) {
    (void) index; // for multiple configurations

    static uint8_t initd = 0;
    if (initd == 0) {
        uint8_t *p = desc_config_extended;
        memcpy(p, &desc_config, sizeof(tusb_desc_configuration_t));
        p += sizeof(tusb_desc_configuration_t);
#ifdef USB_ITF_HID
        memcpy(p, &desc_hid, sizeof(desc_hid)); p += sizeof(desc_hid);
        memcpy(p, &desc_hid_kb, sizeof(desc_hid_kb)); p += sizeof(desc_hid_kb);
#endif
#ifdef USB_ITF_CCID
        memcpy(p, &desc_interface, sizeof(tusb_desc_interface_t));
        p += sizeof(tusb_desc_interface_t);
        memcpy(p, &desc_ccid, sizeof(struct ccid_class_descriptor));
        p += sizeof(struct ccid_class_descriptor);
        memcpy(p, &desc_ep1, sizeof(tusb_desc_endpoint_t)); p += sizeof(tusb_desc_endpoint_t);
        memcpy(p, &desc_ep2, sizeof(tusb_desc_endpoint_t)); p += sizeof(tusb_desc_endpoint_t);
        memcpy(p, &desc_ep3, sizeof(tusb_desc_endpoint_t)); p += sizeof(tusb_desc_endpoint_t);
#endif
        initd = 1;
    }
    return (const uint8_t *) desc_config_extended;
}

#define BOS_TOTAL_LEN      (TUD_BOS_DESC_LEN)

#define MS_OS_20_DESC_LEN  0xB2

uint8_t const desc_bos[] = {
    // total length, number of device caps
    TUD_BOS_DESCRIPTOR(BOS_TOTAL_LEN, 2)
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
    "Pico Key Config"               // 4: Vendor Interface
#ifdef USB_ITF_HID
    , "Pico Key HID Interface"
    , "Pico Key HID Keyboard Interface"
#endif
#ifdef USB_ITF_CCID
    , "Pico Key CCID Interface"
#endif
};

static uint16_t _desc_str[32];

uint16_t const *tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
    (void) langid;

    uint8_t chr_count;

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
        char unique_id_str[2 * PICO_UNIQUE_BOARD_ID_SIZE_BYTES + 1];
        if (index == 3) {
            pico_unique_board_id_t unique_id;
            pico_get_unique_board_id(&unique_id);
            pico_get_unique_board_id_string(unique_id_str, 2 * PICO_UNIQUE_BOARD_ID_SIZE_BYTES + 1);
            str = unique_id_str;
        }

        chr_count = strlen(str);
        if (chr_count > 31) {
            chr_count = 31;
        }

        // Convert ASCII string into UTF-16
        for (uint8_t i = 0; i < chr_count; i++) {
            _desc_str[1 + i] = str[i];
        }
    }

    _desc_str[0] = (TUSB_DESC_STRING << 8) | (2 * chr_count + 2);

    return _desc_str;
}
