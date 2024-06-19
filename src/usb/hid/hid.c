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

#ifndef ENABLE_EMULATION
#include "tusb.h"
#ifndef ESP_PLATFORM
#include "bsp/board.h"
#endif
#endif
#include "ctap_hid.h"
#include "pico_keys.h"
#include "pico_keys_version.h"
#include "apdu.h"
#include "usb.h"

static bool mounted = false;
void (*init_fido_cb)() = NULL;
bool is_nitrokey = false;
uint8_t (*get_version_major)() = NULL;
uint8_t (*get_version_minor)() = NULL;
int (*cbor_process_cb)(uint8_t, const uint8_t *, size_t) = NULL;

typedef struct msg_packet {
    uint16_t len;
    uint16_t current_len;
    uint8_t data[CTAP_MAX_PACKET_SIZE];
} __attribute__((__packed__)) msg_packet_t;

msg_packet_t msg_packet = { 0 };

void tud_mount_cb() {
    mounted = true;
}

bool driver_mounted_hid() {
    return mounted;
}

CTAPHID_FRAME *ctap_req = NULL, *ctap_resp = NULL;
void send_keepalive();
int driver_init_hid() {
#ifndef ENABLE_EMULATION
    tud_init(BOARD_TUD_RHPORT);
#endif
    ctap_req = (CTAPHID_FRAME *) usb_get_rx(ITF_HID);
    apdu.header = ctap_req->init.data;

    ctap_resp = (CTAPHID_FRAME *) usb_get_tx(ITF_HID);
    apdu.rdata = ctap_resp->init.data;

    usb_set_timeout_counter(ITF_HID, 200);

    is_nitrokey = false;
    return 0;
}

uint16_t send_buffer_size[ITF_TOTAL] = {0};
bool last_write_result[ITF_TOTAL] = {false};

uint16_t *get_send_buffer_size(uint8_t itf) {
    return &send_buffer_size[itf];
}

//--------------------------------------------------------------------+
// USB HID
//--------------------------------------------------------------------+

#ifndef ENABLE_EMULATION

uint16_t (*hid_get_report_cb)(uint8_t, uint8_t, hid_report_type_t, uint8_t *, uint16_t) = NULL;
// Invoked when received GET_REPORT control request
// Application must fill buffer report's content and return its length.
// Return zero will cause the stack to STALL request

uint16_t tud_hid_get_report_cb(uint8_t itf,
                               uint8_t report_id,
                               hid_report_type_t report_type,
                               uint8_t *buffer,
                               uint16_t reqlen) {
    // TODO not Implemented
    (void) itf;
    (void) report_id;
    (void) report_type;
    (void) buffer;
    (void) reqlen;
    printf("get_report %d %d %d\n", itf, report_id, report_type);
    DEBUG_PAYLOAD(buffer, reqlen);
    if (hid_get_report_cb) {
        hid_get_report_cb(itf, report_id, report_type, buffer, reqlen);
    }
    return reqlen;
}
#endif

uint32_t hid_write_offset(uint16_t size, uint16_t offset) {
    if (*usb_get_tx(ITF_HID) != 0x81) {
        DEBUG_PAYLOAD(usb_get_tx(ITF_HID) + offset, size);
    }
    return usb_write_offset(ITF_HID, size, offset);
}

uint32_t hid_write(uint16_t size) {
    return hid_write_offset(size, 0);
}

#ifndef ENABLE_EMULATION
static uint8_t keyboard_buffer[256];
static uint8_t keyboard_buffer_len = 0;
static const uint8_t conv_table[128][2] =  { HID_ASCII_TO_KEYCODE };
static uint8_t keyboard_w = 0;
static bool sent_key = false;
static bool keyboard_encode = false;

void add_keyboard_buffer(const uint8_t *data, size_t data_len, bool encode) {
    keyboard_buffer_len = MIN(sizeof(keyboard_buffer), data_len);
    memcpy(keyboard_buffer, data, keyboard_buffer_len);
    keyboard_encode = encode;
}

void append_keyboard_buffer(const uint8_t *data, size_t data_len) {
    if (keyboard_buffer_len < sizeof(keyboard_buffer)) {
        memcpy(keyboard_buffer + keyboard_buffer_len, data, MIN(sizeof(keyboard_buffer) - keyboard_buffer_len, data_len));
        keyboard_buffer_len += MIN(sizeof(keyboard_buffer) - keyboard_buffer_len, data_len);
    }
}

static void send_hid_report(uint8_t report_id) {
    if (!tud_hid_ready()) {
        return;
    }

    switch (report_id) {
        case REPORT_ID_KEYBOARD: {
            if (keyboard_w < keyboard_buffer_len) {
                if (sent_key == false) {
                    uint8_t keycode[6] = { 0 };
                    uint8_t modifier = 0;
                    uint8_t chr = keyboard_buffer[keyboard_w];
                    if (keyboard_encode) {
                        if (conv_table[chr][0]) {
                            modifier = KEYBOARD_MODIFIER_LEFTSHIFT;
                        }
                        keycode[0] = conv_table[chr][1];
                    }
                    else {
                        if (chr & 0x80) {
                            modifier = KEYBOARD_MODIFIER_LEFTSHIFT;
                        }
                        keycode[0] = chr & 0x7f;
                    }
                    if (tud_hid_n_keyboard_report(ITF_KEYBOARD, REPORT_ID_KEYBOARD, modifier,
                                                  keycode) == true) {
                        sent_key = true;
                    }
                }
                else {
                    if (tud_hid_n_keyboard_report(ITF_KEYBOARD, REPORT_ID_KEYBOARD, 0,
                                                  NULL) == true) {
                        keyboard_w++;
                        sent_key = false;

                    }
                }
            }
            else if (keyboard_w == keyboard_buffer_len && keyboard_buffer_len > 0) {
                keyboard_w = keyboard_buffer_len = 0;
            }
        }
        break;

        default: break;
    }
}

void hid_task(void) {
    // Poll every 10ms
    const uint32_t interval_ms = 10;
    static uint32_t start_ms = 0;

    if (board_millis() - start_ms < interval_ms) {
        return;
    }
    start_ms += interval_ms;

    // Remote wakeup
    if (tud_suspended() && keyboard_buffer_len > 0) {
        tud_remote_wakeup();
    }
    else {
        send_hid_report(REPORT_ID_KEYBOARD);
    }
}
#endif

void tud_hid_report_complete_cb(uint8_t instance, uint8_t const *report, uint16_t len) {
    if (send_buffer_size[instance] > 0 && instance == ITF_HID) {
        uint8_t seq = report[4] & TYPE_MASK ? 0 : report[4] + 1;
        if (last_write_result[instance] == true) {
            ctap_resp->cid = ctap_req->cid;
            ctap_resp->cont.seq = seq;
        }
        if (hid_write_offset(64, (uint8_t *) ctap_resp - (usb_get_tx(ITF_HID))) > 0) {
            send_buffer_size[instance] -= MIN(64 - 5, send_buffer_size[instance]);
            ctap_resp = (CTAPHID_FRAME *) ((uint8_t *) ctap_resp + 64 - 5);
        }
    }
}

#ifndef ENABLE_EMULATION
int driver_write_hid(uint8_t itf, const uint8_t *buffer, uint16_t buffer_size) {
    last_write_result[itf] = tud_hid_n_report(itf, 0, buffer, buffer_size);
    printf("result %d\n", last_write_result[itf]);
    if (last_write_result[itf] == false) {
        return 0;
    }
    return MIN(64, buffer_size);
}
#endif

uint16_t driver_read_hid(uint8_t *buffer, uint16_t buffer_size) {
    return 0;
}

#ifndef ENABLE_EMULATION

int (*hid_set_report_cb)(uint8_t, uint8_t, hid_report_type_t, uint8_t const *, uint16_t) = NULL;
// Invoked when received SET_REPORT control request or
// received data on OUT endpoint ( Report ID = 0, Type = 0 )

void tud_hid_set_report_cb(uint8_t itf,
                           uint8_t report_id,
                           hid_report_type_t report_type,
                           uint8_t const *buffer,
                           uint16_t bufsize)
{
    // This example doesn't use multiple report and report ID
    (void) itf;
    (void) report_id;
    (void) report_type;
    printf("set_report %d %d %d\n", itf, report_id, report_type);
    if (!hid_set_report_cb || hid_set_report_cb(itf, report_id, report_type, buffer, bufsize) == 0) {
        usb_rx(itf, buffer, bufsize);
    }
}
#endif

uint32_t last_cmd_time = 0, last_packet_time = 0;
int ctap_error(uint8_t error) {
    ctap_resp = (CTAPHID_FRAME *) usb_get_tx(ITF_HID);
    memset(ctap_resp, 0, sizeof(CTAPHID_FRAME));
    ctap_resp->cid = ctap_req->cid;
    ctap_resp->init.cmd = CTAPHID_ERROR;
    ctap_resp->init.bcntl = 1;
    ctap_resp->init.data[0] = error;
    hid_write(64);
    usb_clear_rx(ITF_HID);
    last_packet_time = 0;
    return 0;
}

uint8_t last_cmd = 0;
uint8_t last_seq = 0;
CTAPHID_FRAME last_req = { 0 };
uint32_t lock = 0;

uint8_t thread_type = 0; //1 is APDU, 2 is CBOR
void (*cbor_thread_func)() = NULL;
extern bool cancel_button;

int driver_process_usb_nopacket_hid() {
    if (last_packet_time > 0 && last_packet_time + 500 < board_millis()) {
        ctap_error(CTAP1_ERR_MSG_TIMEOUT);
        last_packet_time = 0;
        msg_packet.len = msg_packet.current_len = 0;
    }
    return 0;
}

const uint8_t *fido_aid = NULL;

int driver_process_usb_packet_hid(uint16_t read) {
    int apdu_sent = 0;
    if (read >= 5) {
        driver_init_hid();
        last_packet_time = board_millis();
        DEBUG_PAYLOAD(usb_get_rx(ITF_HID), 64);
        memset(ctap_resp, 0, sizeof(CTAPHID_FRAME));
        if (ctap_req->cid == 0x0 ||
            (ctap_req->cid == CID_BROADCAST && ctap_req->init.cmd != CTAPHID_INIT)) {
            return ctap_error(CTAP1_ERR_INVALID_CHANNEL);
        }
        if (board_millis() < lock && ctap_req->cid != last_req.cid &&
            last_cmd_time + 100 > board_millis()) {
            return ctap_error(CTAP1_ERR_CHANNEL_BUSY);
        }
        if (FRAME_TYPE(ctap_req) == TYPE_INIT) {
            if (MSG_LEN(ctap_req) > CTAP_MAX_PACKET_SIZE) {
                return ctap_error(CTAP1_ERR_INVALID_LEN);
            }
            if (msg_packet.len > 0 && last_cmd_time + 100 > board_millis() &&
                ctap_req->init.cmd != CTAPHID_INIT) {
                if (last_req.cid != ctap_req->cid) { //We are in a transaction
                    return ctap_error(CTAP1_ERR_CHANNEL_BUSY);
                }
                else {
                    return ctap_error(CTAP1_ERR_INVALID_SEQ);
                }
            }
            printf("command %x\n", FRAME_CMD(ctap_req));
            printf("len %d\n", MSG_LEN(ctap_req));
            msg_packet.len = msg_packet.current_len = 0;
            if (MSG_LEN(ctap_req) > 64 - 7) {
                msg_packet.len = MSG_LEN(ctap_req);
                memcpy(msg_packet.data + msg_packet.current_len, ctap_req->init.data, 64 - 7);
                msg_packet.current_len += 64 - 7;
            }
            memcpy(&last_req, ctap_req, sizeof(CTAPHID_FRAME));
            last_cmd = ctap_req->init.cmd;
            last_seq = 0;
            last_cmd_time = board_millis();
        }
        else {
            if (msg_packet.len == 0) { //Received a cont with a prior init pkt
                return 0;
            }
            if (last_seq != ctap_req->cont.seq) {
                return ctap_error(CTAP1_ERR_INVALID_SEQ);
            }
            if (last_req.cid == ctap_req->cid) {
                memcpy(msg_packet.data + msg_packet.current_len, ctap_req->cont.data,
                       MIN(64 - 5, msg_packet.len - msg_packet.current_len));
                msg_packet.current_len += MIN(64 - 5, msg_packet.len - msg_packet.current_len);
                memcpy(&last_req, ctap_req, sizeof(CTAPHID_FRAME));
                last_seq++;
            }
            else if (last_cmd_time + 100 > board_millis()) {
                return ctap_error(CTAP1_ERR_CHANNEL_BUSY);
            }

        }

        if (ctap_req->init.cmd == CTAPHID_INIT) {
            if (init_fido_cb) {
                init_fido_cb();
            }
            ctap_resp = (CTAPHID_FRAME *) usb_get_tx(ITF_HID);
            memset(ctap_resp, 0, 64);
            CTAPHID_INIT_REQ *req = (CTAPHID_INIT_REQ *) ctap_req->init.data;
            CTAPHID_INIT_RESP *resp = (CTAPHID_INIT_RESP *) ctap_resp->init.data;
            memcpy(resp->nonce, req->nonce, sizeof(resp->nonce));
            resp->cid = 0x01000000;
            resp->versionInterface = CTAPHID_IF_VERSION;
            resp->versionMajor = get_version_major ? get_version_major() : PICO_KEYS_SDK_VERSION_MAJOR;
            resp->versionMinor = get_version_minor ? get_version_minor() : PICO_KEYS_SDK_VERSION_MINOR;
            resp->capFlags = CAPFLAG_WINK | CAPFLAG_CBOR;

            ctap_resp->cid = ctap_req->cid;
            ctap_resp->init.cmd = CTAPHID_INIT;
            ctap_resp->init.bcntl = 17;
            ctap_resp->init.bcnth = 0;
            hid_write(64);
            msg_packet.len = msg_packet.current_len = 0;
            last_packet_time = 0;
        }
        else if (ctap_req->init.cmd == CTAPHID_WINK) {
            if (MSG_LEN(ctap_req) != 0) {
                return ctap_error(CTAP1_ERR_INVALID_LEN);
            }
            ctap_resp = (CTAPHID_FRAME *) usb_get_tx(ITF_HID);
            memcpy(ctap_resp, ctap_req, sizeof(CTAPHID_FRAME));
#ifndef ENABLE_EMULATION
            sleep_ms(1000); //For blinking the device during 1 seg
#endif
            hid_write(64);
            msg_packet.len = msg_packet.current_len = 0;
            last_packet_time = 0;
        }
        else if ((last_cmd == CTAPHID_PING || last_cmd == CTAPHID_SYNC) &&
                 (msg_packet.len == 0 ||
                  (msg_packet.len == msg_packet.current_len && msg_packet.len > 0))) {
            ctap_resp = (CTAPHID_FRAME *) usb_get_tx(ITF_HID);
            if (msg_packet.current_len == msg_packet.len && msg_packet.len > 0) {
                memcpy(ctap_resp->init.data, msg_packet.data, msg_packet.len);
                driver_exec_finished_hid(msg_packet.len);
            }
            else {
                memcpy(ctap_resp->init.data, ctap_req->init.data, MSG_LEN(ctap_req));
                ctap_resp->cid = ctap_req->cid;
                ctap_resp->init.cmd = last_cmd;
                ctap_resp->init.bcnth = MSG_LEN(ctap_req) >> 8;
                ctap_resp->init.bcntl = MSG_LEN(ctap_req) & 0xff;
                hid_write(64);
            }
            msg_packet.len = msg_packet.current_len = 0;
            last_packet_time = 0;
        }
        else if (ctap_req->init.cmd == CTAPHID_LOCK) {
            if (MSG_LEN(ctap_req) != 1) {
                return ctap_error(CTAP1_ERR_INVALID_LEN);
            }
            if (ctap_req->init.data[0] > 10) {
                return ctap_error(CTAP1_ERR_INVALID_PARAMETER);
            }
            lock = board_millis() + ctap_req->init.data[0] * 1000;
            ctap_resp = (CTAPHID_FRAME *) usb_get_tx(ITF_HID);
            memset(ctap_resp, 0, 64);
            ctap_resp->cid = ctap_req->cid;
            ctap_resp->init.cmd = ctap_req->init.cmd;
            hid_write(64);
            msg_packet.len = msg_packet.current_len = 0;
            last_packet_time = 0;
        }
        else if (ctap_req->init.cmd == CTAPHID_UUID) {
            ctap_resp = (CTAPHID_FRAME *) usb_get_tx(ITF_HID);
            memset(ctap_resp, 0, 64);
            ctap_resp->cid = ctap_req->cid;
            ctap_resp->init.cmd = ctap_req->init.cmd;
            memcpy(ctap_resp->init.data, pico_serial.id, sizeof(pico_serial.id));
            ctap_resp->init.bcntl = 16;
            hid_write(64);
            msg_packet.len = msg_packet.current_len = 0;
            last_packet_time = 0;
        }
        else if (ctap_req->init.cmd == CTAPHID_VERSION) {
            ctap_resp = (CTAPHID_FRAME *) usb_get_tx(ITF_HID);
            memset(ctap_resp, 0, 64);
            ctap_resp->cid = ctap_req->cid;
            ctap_resp->init.cmd = ctap_req->init.cmd;
            ctap_resp->init.data[0] = PICO_KEYS_SDK_VERSION_MAJOR;
            ctap_resp->init.data[1] = PICO_KEYS_SDK_VERSION_MINOR;
            ctap_resp->init.bcntl = 4;
            hid_write(64);
            msg_packet.len = msg_packet.current_len = 0;
            last_packet_time = 0;
        }
        else if (ctap_req->init.cmd == CTAPHID_ADMIN) {
            ctap_resp = (CTAPHID_FRAME *) usb_get_tx(ITF_HID);
            memset(ctap_resp, 0, 64);
            ctap_resp->cid = ctap_req->cid;
            ctap_resp->init.cmd = ctap_req->init.cmd;
            if (ctap_req->init.data[0] == 0x80) { // Status
                memcpy(ctap_resp->init.data, "\x00\xff\xff\xff\x00", 5);
                ctap_resp->init.bcntl = 5;
            }
            hid_write(64);
            msg_packet.len = msg_packet.current_len = 0;
            last_packet_time = 0;
        }
        else if ((last_cmd == CTAPHID_MSG || last_cmd == CTAPHID_OTP) &&
                 (msg_packet.len == 0 ||
                  (msg_packet.len == msg_packet.current_len && msg_packet.len > 0))) {
            if (last_cmd == CTAPHID_OTP) {
                is_nitrokey = true;
            }

            else if (current_app == NULL ||
                current_app->aid != fido_aid) {
                    if (current_app && current_app->unload) {
                        current_app->unload();
                    }
                    for (int a = 0; a < num_apps; a++) {
                        if (!memcmp(apps[a].aid + 1, fido_aid + 1, MIN(fido_aid[0], apps[a].aid[0]))) {
                            current_app = &apps[a];
                            current_app->select_aid(current_app);
                        }
                    }
            }
            //if (thread_type != 1)
#ifndef ENABLE_EMULATION
            card_start(apdu_thread);
#endif
            thread_type = 1;

            if (msg_packet.current_len == msg_packet.len && msg_packet.len > 0) {
                apdu_sent = apdu_process(ITF_HID, msg_packet.data, msg_packet.len);
            }
            else {
                apdu_sent = apdu_process(ITF_HID, ctap_req->init.data, MSG_LEN(ctap_req));
            }
            DEBUG_PAYLOAD(apdu.data, (int) apdu.nc);
            msg_packet.len = msg_packet.current_len = 0;
            last_packet_time = 0;
        }
        else if ((last_cmd == CTAPHID_CBOR ||
                  (last_cmd >= CTAPHID_VENDOR_FIRST && last_cmd <= CTAPHID_VENDOR_LAST)) &&
                 (msg_packet.len == 0 ||
                  (msg_packet.len == msg_packet.current_len && msg_packet.len > 0))) {

            //if (thread_type != 2)
#ifndef ENABLE_EMULATION
            card_start(cbor_thread_func);
#endif
            thread_type = 2;
            if (cbor_process_cb) {
                if (msg_packet.current_len == msg_packet.len && msg_packet.len > 0) {
                    apdu_sent = cbor_process_cb(last_cmd, msg_packet.data, msg_packet.len);
                }
                else {
                    apdu_sent = cbor_process_cb(last_cmd, ctap_req->init.data, MSG_LEN(ctap_req));
                }
            }
            msg_packet.len = msg_packet.current_len = 0;
            last_packet_time = 0;
            if (apdu_sent < 0) {
                return ctap_error(-apdu_sent);
            }
            send_keepalive();
        }
        else if (ctap_req->init.cmd == CTAPHID_CANCEL) {
            ctap_error(0x2D);
            msg_packet.len = msg_packet.current_len = 0;
            last_packet_time = 0;
            cancel_button = true;
        }
        else {
            if (msg_packet.len == 0) {
                return ctap_error(CTAP1_ERR_INVALID_CMD);
            }
        }
        // echo back anything we received from host
        //tud_hid_report(0, buffer, bufsize);
        //printf("END\n");
        usb_clear_rx(ITF_HID);
    }
    return apdu_sent;
}

void send_keepalive() {
    CTAPHID_FRAME *resp = (CTAPHID_FRAME *) (usb_get_tx(ITF_HID) + 4096);
    //memset(ctap_resp, 0, sizeof(CTAPHID_FRAME));
    resp->cid = ctap_req->cid;
    resp->init.cmd = CTAPHID_KEEPALIVE;
    resp->init.bcntl = 1;
    resp->init.data[0] = is_req_button_pending() ? 2 : 1;
    send_buffer_size[ITF_HID] = 0;
    hid_write_offset(64, 4096);
}

void driver_exec_timeout_hid() {
    if (thread_type == 2) {
        send_keepalive();
    }
}

uint8_t *driver_prepare_response_hid() {
    ctap_resp = (CTAPHID_FRAME *) usb_get_tx(ITF_HID);
    apdu.rdata = ctap_resp->init.data;
    send_buffer_size[ITF_HID] = 0;
    memset(usb_get_tx(ITF_HID), 0, 4096);
    return ctap_resp->init.data;
}

void driver_exec_finished_hid(uint16_t size_next) {
    if (size_next > 0) {
        if (thread_type == 2 && apdu.sw != 0) {
            ctap_error(apdu.sw & 0xff);
        }
        else {
            if (is_nitrokey) {
                memmove(apdu.rdata + 2, apdu.rdata, size_next - 2);
                apdu.rdata[0] = apdu.sw >> 8;
                apdu.rdata[1] = apdu.sw & 0xff;
            }
            driver_exec_finished_cont_hid(size_next, 7);
        }
    }
    apdu.sw = 0;
}

void driver_exec_finished_cont_hid(uint16_t size_next, uint16_t offset) {
    offset -= 7;
    ctap_resp = (CTAPHID_FRAME *) (usb_get_tx(ITF_HID) + offset);
    ctap_resp->cid = ctap_req->cid;
    ctap_resp->init.cmd = last_cmd;
    ctap_resp->init.bcnth = size_next >> 8;
    ctap_resp->init.bcntl = size_next & 0xff;
    send_buffer_size[ITF_HID] = size_next;
    if (hid_write_offset(64, offset) > 0) {
        ctap_resp = (CTAPHID_FRAME *) ((uint8_t *) ctap_resp + 64 - 5);
        send_buffer_size[ITF_HID] -= MIN(64 - 7, send_buffer_size[ITF_HID]);
    }
}
