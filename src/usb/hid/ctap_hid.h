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

#ifndef _CTAP_HID_H_
#define _CTAP_HID_H_

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "usb.h"

// Size of HID reports

#define HID_RPT_SIZE            64      // Default size of raw HID report

// Frame layout - command- and continuation frames

#define CID_BROADCAST           0xffffffff // Broadcast channel id

#define TYPE_MASK               0x80    // Frame type mask
#define TYPE_INIT               0x80    // Initial frame identifier
#define TYPE_CONT               0x00    // Continuation frame identifier

PACK(
typedef struct {
    uint32_t cid;                      // Channel identifier
    union {
        uint8_t type;                  // Frame type - b7 defines type
        struct {
            uint8_t cmd;               // Command - b7 set
            uint8_t bcnth;             // Message byte count - high part
            uint8_t bcntl;             // Message byte count - low part
            uint8_t data[HID_RPT_SIZE - 7]; // Data payload
        } init;
        struct {
            uint8_t seq;               // Sequence number - b7 cleared
            uint8_t data[HID_RPT_SIZE - 5]; // Data payload
        } cont;
    };
}) CTAPHID_FRAME;

extern CTAPHID_FRAME *ctap_req, *ctap_resp;

#define FRAME_TYPE(f) ((f)->type & TYPE_MASK)
#define FRAME_CMD(f)  ((f)->init.cmd & ~TYPE_MASK)
#define MSG_LEN(f)    ((f)->init.bcnth * 256 + (f)->init.bcntl)
#define FRAME_SEQ(f)  ((f)->cont.seq & ~TYPE_MASK)

// HID usage- and usage-page definitions

#define FIDO_USAGE_PAGE         0xf1d0  // FIDO alliance HID usage page
#define FIDO_USAGE_CTAPHID       0x01    // CTAPHID usage for top-level collection
#define FIDO_USAGE_DATA_IN      0x20    // Raw IN data report
#define FIDO_USAGE_DATA_OUT     0x21    // Raw OUT data report

// General constants

#define CTAPHID_IF_VERSION       2       // Current interface implementation version
#define CTAPHID_TRANS_TIMEOUT    3000    // Default message timeout in ms

// CTAPHID native commands

#define CTAPHID_PING         (TYPE_INIT | 0x01)  // Echo data through local processor only
#define CTAPHID_MSG          (TYPE_INIT | 0x03)  // Send CTAP message frame
#define CTAPHID_LOCK         (TYPE_INIT | 0x04)  // Send lock channel command
#define CTAPHID_INIT         (TYPE_INIT | 0x06)  // Channel initialization
#define CTAPHID_WINK         (TYPE_INIT | 0x08)  // Send device identification wink
#define CTAPHID_CBOR         (TYPE_INIT | 0x10)  // CBOR
#define CTAPHID_CANCEL       (TYPE_INIT | 0x11)  // Cancel any request
#define CTAPHID_KEEPALIVE    (TYPE_INIT | 0x3B)  // Keepalive command
#define CTAPHID_SYNC         (TYPE_INIT | 0x3C)  // Protocol resync command
#define CTAPHID_ERROR        (TYPE_INIT | 0x3F)  // Error response

#define CTAPHID_UPDATE       (TYPE_INIT | 0x51)
#define CTAPHID_REBOOT       (TYPE_INIT | 0x53)
#define CTAPHID_RNG          (TYPE_INIT | 0x60)
#define CTAPHID_VERSION      (TYPE_INIT | 0x61)
#define CTAPHID_UUID         (TYPE_INIT | 0x62)
#define CTAPHID_LOCKED       (TYPE_INIT | 0x63)
#define CTAPHID_OTP          (TYPE_INIT | 0x70)
#define CTAPHID_PROVISIONER  (TYPE_INIT | 0x71)
#define CTAPHID_ADMIN        (TYPE_INIT | 0x72)

#define CTAPHID_VENDOR_FIRST (TYPE_INIT | 0x40)  // First vendor defined command
#define CTAPHID_VENDOR_LAST  (TYPE_INIT | 0x7F)  // Last vendor defined command

// CTAP_KEEPALIVE command defines

#define KEEPALIVE_STATUS_PROCESSING     0x1
#define KEEPALIVE_STATUS_UPNEEDED       0x2

// CTAPHID_INIT command defines

#define INIT_NONCE_SIZE         8       // Size of channel initialization challenge
#define CAPFLAG_WINK            0x01    // Device supports WINK command
#define CAPFLAG_CBOR            0x04    // Device supports CBOR command

PACK(
typedef struct {
    uint8_t nonce[INIT_NONCE_SIZE];     // Client application nonce
}) CTAPHID_INIT_REQ;

PACK(
typedef struct {
    uint8_t nonce[INIT_NONCE_SIZE];     // Client application nonce
    uint32_t cid;                       // Channel identifier
    uint8_t versionInterface;           // Interface version
    uint8_t versionMajor;               // Major version number
    uint8_t versionMinor;               // Minor version number
    uint8_t versionBuild;               // Build version number
    uint8_t capFlags;                   // Capabilities flags
}) CTAPHID_INIT_RESP;

// CTAPHID_SYNC command defines

typedef struct {
    uint8_t nonce;                      // Client application nonce
} CTAPHID_SYNC_REQ;

typedef struct {
    uint8_t nonce;                      // Client application nonce
} CTAPHID_SYNC_RESP;

// Low-level error codes. Return as negatives.

#define CTAP_MAX_PACKET_SIZE    (64 - 7 + 128 * (64 - 5))
#define CTAP_MAX_CBOR_PAYLOAD   (USB_BUFFER_SIZE - 64 - 7 - 1)

#define CTAP1_ERR_NONE                0x00    // No error
#define CTAP1_ERR_INVALID_CMD         0x01    // Invalid command
#define CTAP1_ERR_INVALID_PARAMETER   0x02    // Invalid parameter
#define CTAP1_ERR_INVALID_LEN         0x03    // Invalid message length
#define CTAP1_ERR_INVALID_SEQ         0x04    // Invalid message sequencing
#define CTAP1_ERR_MSG_TIMEOUT         0x05    // Message has timed out
#define CTAP1_ERR_CHANNEL_BUSY        0x06    // Channel busy
#define CTAP1_ERR_LOCK_REQUIRED       0x0a    // Command requires channel lock
#define CTAP1_ERR_INVALID_CHANNEL     0x0b    // CID not valid
#define CTAP1_ERR_OTHER               0x7f    // Other unspecified error

extern void add_keyboard_buffer(const uint8_t *, size_t, bool);
extern void append_keyboard_buffer(const uint8_t *data, size_t data_len);

extern bool is_nitrokey;

#ifdef __cplusplus
}
#endif

#endif  // _CTAP_HID_H_
