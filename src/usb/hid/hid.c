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
#else
static portMUX_TYPE mutex = portMUX_INITIALIZER_UNLOCKED;
#endif
#else
#include "emulation.h"
#endif
#include "ctap_hid.h"
#include "pico_keys.h"
#include "pico_keys_version.h"
#include "apdu.h"
#include "usb.h"

static bool mounted = false;
extern void init_fido();
bool is_nitrokey = false;
uint8_t (*get_version_major)() = NULL;
uint8_t (*get_version_minor)() = NULL;

static usb_buffer_t hid_rx[ITF_HID_TOTAL] = {0}, hid_tx[ITF_HID_TOTAL] = {0};

PACK(
typedef struct msg_packet {
    uint16_t len;
    uint16_t current_len;
    uint8_t data[CTAP_MAX_PACKET_SIZE];
}) msg_packet_t;

msg_packet_t msg_packet = { 0 };

void tud_mount_cb() {
    mounted = true;
}

bool driver_mounted_hid() {
    return mounted;
}

static uint16_t send_buffer_size[ITF_HID_TOTAL] = {0};
static write_status_t last_write_result[ITF_HID_TOTAL] = {0};

CTAPHID_FRAME *ctap_req = NULL, *ctap_resp = NULL;
void send_keepalive();
int driver_process_usb_packet_hid(uint16_t read);
int driver_write_hid(uint8_t itf, const uint8_t *buffer, uint16_t buffer_size);
int driver_process_usb_nopacket_hid();

int driver_init_hid() {
#ifndef ENABLE_EMULATION
    static bool _init = false;
    if (_init == false) {
        tud_init(BOARD_TUD_RHPORT);
        _init = true;
    }
#endif
    ctap_req = (CTAPHID_FRAME *) (hid_rx[ITF_HID_CTAP].buffer + hid_rx[ITF_HID_CTAP].r_ptr);
    apdu.header = ctap_req->init.data;

    ctap_resp = (CTAPHID_FRAME *) (hid_tx[ITF_HID_CTAP].buffer);
    apdu.rdata = ctap_resp->init.data;
    //memset(ctap_resp, 0, sizeof(CTAPHID_FRAME));

    usb_set_timeout_counter(ITF_HID, 200);

    is_nitrokey = false;

    hid_tx[ITF_HID_CTAP].w_ptr = hid_tx[ITF_HID_CTAP].r_ptr = 0;
    send_buffer_size[ITF_HID_CTAP] = 0;
    return 0;
}

uint16_t *get_send_buffer_size(uint8_t itf) {
    return &send_buffer_size[itf];
}

//--------------------------------------------------------------------+
// USB HID
//--------------------------------------------------------------------+

uint16_t (*hid_get_report_cb)(uint8_t, uint8_t, hid_report_type_t, uint8_t *, uint16_t) = NULL;
// Invoked when received GET_REPORT control request
// Application must fill buffer report's content and return its length.
// Return zero will cause the stack to STALL request

uint16_t tud_hid_get_report_cb(uint8_t itf, uint8_t report_id, hid_report_type_t report_type, uint8_t *buffer, uint16_t reqlen) {
    // TODO not Implemented
    (void) itf;
    (void) report_id;
    (void) report_type;
    (void) buffer;
    (void) reqlen;
    printf("get_report %d %d %d\n", itf, report_id, report_type);
    memset(buffer, 0, reqlen);
    DEBUG_PAYLOAD(buffer, reqlen);
    if (hid_get_report_cb) {
        hid_get_report_cb(itf, report_id, report_type, buffer, reqlen);
    }
    return reqlen;
}

uint32_t hid_write_offset(uint16_t size, uint16_t offset) {
    if (hid_tx[ITF_HID_CTAP].buffer[offset] != 0x81) {
        DEBUG_PAYLOAD(&hid_tx[ITF_HID_CTAP].buffer[offset], size);
    }
    hid_tx[ITF_HID_CTAP].w_ptr += size + offset;
    hid_tx[ITF_HID_CTAP].r_ptr += offset;
    return size;
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
    if (keyboard_buffer_len + data_len < sizeof(keyboard_buffer)) {
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
                    if (tud_hid_n_keyboard_report(ITF_HID_KB, REPORT_ID_KEYBOARD, modifier, keycode) == true) {
                        sent_key = true;
                    }
                }
                else {
                    if (tud_hid_n_keyboard_report(ITF_HID_KB, REPORT_ID_KEYBOARD, 0, NULL) == true) {
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
#endif

void tud_hid_report_complete_cb(uint8_t instance, uint8_t const *report, uint16_t len) {
    //printf("report_complete %d %d %d\n", instance, len, send_buffer_size[instance]);
    if (instance == ITF_HID_CTAP && len > 0) {
#ifdef ESP_PLATFORM
        taskENTER_CRITICAL(&mutex);
#endif
        CTAPHID_FRAME *req = (CTAPHID_FRAME *) report;
        if (last_write_result[instance] == WRITE_PENDING) {
            last_write_result[instance] = WRITE_SUCCESS;
            if (FRAME_TYPE(req) == TYPE_INIT) {
                if (req->init.cmd != CTAPHID_KEEPALIVE) {
                    send_buffer_size[instance] -= MIN(64 - 7, send_buffer_size[instance]);
                }
            }
            else {
                send_buffer_size[instance] -= MIN(64 - 5, send_buffer_size[instance]);
            }
        }
        if (last_write_result[instance] == WRITE_SUCCESS) {
            if (FRAME_TYPE(req) != TYPE_INIT || req->init.cmd != CTAPHID_KEEPALIVE) {
                if (send_buffer_size[instance] > 0) {
                    ctap_resp = (CTAPHID_FRAME *) ((uint8_t *) ctap_resp + 64 - 5);
                    uint8_t seq = FRAME_TYPE(req) == TYPE_INIT ? 0 : FRAME_SEQ(req) + 1;
                    ctap_resp->cid = req->cid;
                    ctap_resp->cont.seq = seq;

                    hid_tx[ITF_HID_CTAP].r_ptr += 64 - 5;
                }
                else {
                    hid_tx[ITF_HID_CTAP].r_ptr += 64;
                }
            }
        }
        if (hid_tx[ITF_HID_CTAP].r_ptr >= hid_tx[ITF_HID_CTAP].w_ptr) {
            hid_tx[ITF_HID_CTAP].r_ptr = hid_tx[ITF_HID_CTAP].w_ptr = 0;
        }
#ifdef ESP_PLATFORM
        taskEXIT_CRITICAL(&mutex);
#endif
    }
}

int driver_write_hid(uint8_t itf, const uint8_t *buffer, uint16_t buffer_size) {
    if (last_write_result[itf] == WRITE_PENDING) {
        return 0;
    }
    bool r = tud_hid_n_report(itf, 0, buffer, buffer_size);
    last_write_result[itf] = r ? WRITE_PENDING : WRITE_FAILED;
    if (last_write_result[itf] == WRITE_FAILED) {
        return 0;
    }
#ifdef ENABLE_EMULATION
    tud_hid_report_complete_cb(ITF_HID_CTAP, buffer, buffer_size);
#endif
    return MIN(64, buffer_size);
}

int (*hid_set_report_cb)(uint8_t, uint8_t, hid_report_type_t, uint8_t const *, uint16_t) = NULL;
// Invoked when received SET_REPORT control request or
// received data on OUT endpoint ( Report ID = 0, Type = 0 )

void tud_hid_set_report_cb(uint8_t itf, uint8_t report_id, hid_report_type_t report_type, uint8_t const *buffer, uint16_t bufsize) {
    // This example doesn't use multiple report and report ID
    (void) itf;
    (void) report_id;
    (void) report_type;
    printf("set_report %d %d %d\n", itf, report_id, report_type);
    if (!hid_set_report_cb || hid_set_report_cb(itf, report_id, report_type, buffer, bufsize) == 0) {
        //usb_rx(itf, buffer, bufsize);
        memcpy(hid_rx[itf].buffer + hid_rx[itf].w_ptr, buffer, bufsize);
        hid_rx[itf].w_ptr += bufsize;
        int proc_pkt = driver_process_usb_packet_hid(64);
        if (proc_pkt == 0) {
            driver_process_usb_nopacket_hid();
        }
    }
}

uint32_t last_cmd_time = 0, last_packet_time = 0;
int ctap_error(uint8_t error) {
    memset((uint8_t *)ctap_resp, 0, sizeof(CTAPHID_FRAME));
    ctap_resp->cid = ctap_req->cid;
    ctap_resp->init.cmd = CTAPHID_ERROR;
    ctap_resp->init.bcntl = 1;
    ctap_resp->init.data[0] = error;
    hid_write(64);
    last_packet_time = 0;
    return 0;
}

uint8_t last_cmd = 0;
uint8_t last_seq = 0;
CTAPHID_FRAME last_req = { 0 };
uint32_t lock = 0;

uint8_t thread_type = 0; //1 is APDU, 2 is CBOR
extern bool cancel_button;
extern int cbor_process(uint8_t last_cmd, const uint8_t *data, size_t len);

int driver_process_usb_nopacket_hid() {
    if (last_packet_time > 0 && last_packet_time + 500 < board_millis()) {
        ctap_error(CTAP1_ERR_MSG_TIMEOUT);
        last_packet_time = 0;
        msg_packet.len = msg_packet.current_len = 0;
    }
    return 0;
}

extern const uint8_t fido_aid[], u2f_aid[];
extern void apdu_thread(void), cbor_thread(void);

int driver_process_usb_packet_hid(uint16_t read) {
    int apdu_sent = 0;
    if (read >= 5) {
        driver_init_hid();

        hid_rx[ITF_HID_CTAP].r_ptr += 64;
        if (hid_rx[ITF_HID_CTAP].r_ptr >= hid_rx[ITF_HID_CTAP].w_ptr) {
            hid_rx[ITF_HID_CTAP].r_ptr = hid_rx[ITF_HID_CTAP].w_ptr = 0;
        }
        last_packet_time = board_millis();
        DEBUG_PAYLOAD((uint8_t *)ctap_req, 64);
        if (ctap_req->cid == 0x0 ||
            (ctap_req->cid == CID_BROADCAST && (FRAME_TYPE(ctap_req) != TYPE_INIT || ctap_req->init.cmd != CTAPHID_INIT))) {
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
            card_exit();
            hid_tx[ITF_HID_CTAP].r_ptr = hid_tx[ITF_HID_CTAP].w_ptr = 0;
            init_fido();
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
            driver_write_hid(ITF_HID_CTAP, (const uint8_t *)ctap_resp, 64);
            msg_packet.len = msg_packet.current_len = 0;
            last_packet_time = 0;
        }
        else if (ctap_req->init.cmd == CTAPHID_WINK) {
            if (MSG_LEN(ctap_req) != 0) {
                return ctap_error(CTAP1_ERR_INVALID_LEN);
            }
            last_packet_time = 0;
            memcpy(ctap_resp, ctap_req, sizeof(CTAPHID_FRAME));
#ifndef ENABLE_EMULATION
            sleep_ms(1000); //For blinking the device during 1 seg
#endif
            driver_write_hid(ITF_HID_CTAP, (const uint8_t *)ctap_resp, 64);
            msg_packet.len = msg_packet.current_len = 0;
        }
        else if ((last_cmd == CTAPHID_PING || last_cmd == CTAPHID_SYNC) &&
                 (msg_packet.len == 0 ||
                  (msg_packet.len == msg_packet.current_len && msg_packet.len > 0))) {
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
                driver_write_hid(ITF_HID_CTAP, (const uint8_t *)ctap_resp, 64);
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
            ctap_resp->cid = ctap_req->cid;
            ctap_resp->init.cmd = ctap_req->init.cmd;
            driver_write_hid(ITF_HID_CTAP, (const uint8_t *)ctap_resp, 64);
            msg_packet.len = msg_packet.current_len = 0;
            last_packet_time = 0;
        }
        else if (ctap_req->init.cmd == CTAPHID_UUID) {
            ctap_resp->cid = ctap_req->cid;
            ctap_resp->init.cmd = ctap_req->init.cmd;
            memcpy(ctap_resp->init.data, pico_serial.id, sizeof(pico_serial.id));
            ctap_resp->init.bcntl = 16;
            driver_write_hid(ITF_HID_CTAP, (const uint8_t *)ctap_resp, 64);
            msg_packet.len = msg_packet.current_len = 0;
            last_packet_time = 0;
        }
        else if (ctap_req->init.cmd == CTAPHID_VERSION) {
            ctap_resp->cid = ctap_req->cid;
            ctap_resp->init.cmd = ctap_req->init.cmd;
            ctap_resp->init.data[0] = PICO_KEYS_SDK_VERSION_MAJOR;
            ctap_resp->init.data[1] = PICO_KEYS_SDK_VERSION_MINOR;
            ctap_resp->init.bcntl = 4;
            driver_write_hid(ITF_HID_CTAP, (const uint8_t *)ctap_resp, 64);
            msg_packet.len = msg_packet.current_len = 0;
            last_packet_time = 0;
        }
        else if (ctap_req->init.cmd == CTAPHID_ADMIN) {
            ctap_resp->cid = ctap_req->cid;
            ctap_resp->init.cmd = ctap_req->init.cmd;
            if (ctap_req->init.data[0] == 0x80) { // Status
                memcpy(ctap_resp->init.data, "\x00\xff\xff\xff\x00", 5);
                ctap_resp->init.bcntl = 5;
            }
            driver_write_hid(ITF_HID_CTAP, (const uint8_t *)ctap_resp, 64);
            msg_packet.len = msg_packet.current_len = 0;
            last_packet_time = 0;
        }
        else if ((last_cmd == CTAPHID_MSG || last_cmd == CTAPHID_OTP) &&
                 (msg_packet.len == 0 ||
                  (msg_packet.len == msg_packet.current_len && msg_packet.len > 0))) {
            if (last_cmd == CTAPHID_OTP) {
                is_nitrokey = true;
                select_app(fido_aid + 1, fido_aid[0]);
            }
            else {
                select_app(u2f_aid + 1, u2f_aid[0]);
            }

            thread_type = 1;

            if (msg_packet.current_len == msg_packet.len && msg_packet.len > 0) {
                apdu_sent = apdu_process(ITF_HID_CTAP, msg_packet.data, msg_packet.len);
            }
            else {
                apdu_sent = apdu_process(ITF_HID_CTAP, ctap_req->init.data, MSG_LEN(ctap_req));
            }
            DEBUG_PAYLOAD(apdu.data, (int) apdu.nc);
            msg_packet.len = msg_packet.current_len = 0;
            last_packet_time = 0;
        }
        else if ((last_cmd == CTAPHID_CBOR || last_cmd >= CTAPHID_VENDOR_FIRST) &&
                 (msg_packet.len == 0 || (msg_packet.len == msg_packet.current_len && msg_packet.len > 0))) {
            thread_type = 2;
            select_app(fido_aid + 1, fido_aid[0]);
            if (msg_packet.current_len == msg_packet.len && msg_packet.len > 0) {
                apdu_sent = cbor_process(last_cmd, msg_packet.data, msg_packet.len);
            }
            else {
                apdu_sent = cbor_process(last_cmd, ctap_req->init.data, MSG_LEN(ctap_req));
            }
            msg_packet.len = msg_packet.current_len = 0;
            last_packet_time = 0;
            if (apdu_sent < 0) {
                return ctap_error((uint8_t)(-apdu_sent));
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
        if (apdu_sent > 0) {
            if (apdu_sent == 1) {
                card_start(ITF_HID, apdu_thread);
            }
            else if (apdu_sent == 2) {
                card_start(ITF_HID, cbor_thread);
            }
            usb_send_event(EV_CMD_AVAILABLE);
        }
    }
    return apdu_sent;
}

void send_keepalive() {
    CTAPHID_FRAME *resp = (CTAPHID_FRAME *) (hid_tx[ITF_HID_CTAP].buffer + sizeof(hid_tx[ITF_HID_CTAP].buffer) - 64);
    //memset(ctap_resp, 0, sizeof(CTAPHID_FRAME));
    resp->cid = ctap_req->cid;
    resp->init.cmd = CTAPHID_KEEPALIVE;
    resp->init.bcntl = 1;
    resp->init.data[0] = is_req_button_pending() ? 2 : 1;
    //send_buffer_size[ITF_HID_CTAP] = 0;
    driver_write_hid(ITF_HID_CTAP, (const uint8_t *)resp, 64);
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
            driver_exec_finished_cont_hid(ITF_HID_CTAP, size_next, 7);
        }
    }
    apdu.sw = 0;
}

void driver_exec_finished_cont_hid(uint8_t itf, uint16_t size_next, uint16_t offset) {
    offset -= 7;
    ctap_resp = (CTAPHID_FRAME *) (hid_tx[itf].buffer + offset);
    ctap_resp->cid = ctap_req->cid;
    ctap_resp->init.bcnth = size_next >> 8;
    ctap_resp->init.bcntl = size_next & 0xff;
    send_buffer_size[itf] = size_next;
    ctap_resp->init.cmd = last_cmd;
    if (hid_write_offset(size_next+7, offset) > 0) {
        //ctap_resp = (CTAPHID_FRAME *) ((uint8_t *) ctap_resp + 64 - 5);
        //send_buffer_size[ITF_HID_CTAP] -= MIN(64 - 7, send_buffer_size[ITF_HID_CTAP]);
    }
}

void hid_task() {
#ifdef ENABLE_EMULATION
    uint16_t rx_len = emul_read(ITF_HID);
    if (rx_len) {
        uint16_t rptr = 0;
        while (rx_len > 0) {
            tud_hid_set_report_cb(ITF_HID, 0, 0, emul_rx + rptr, 64);
            rx_len -= 64;
            rptr += 64;
        }
        emul_rx_size = 0;
    }
#endif
    int proc_pkt = 0;
    if (hid_rx[ITF_HID_CTAP].w_ptr - hid_rx[ITF_HID_CTAP].r_ptr >= 64) {
        //proc_pkt = driver_process_usb_packet_hid(64);
    }
    if (proc_pkt == 0) {
        driver_process_usb_nopacket_hid();
    }
    int status = card_status(ITF_HID);
    if (status == PICOKEY_OK) {
        driver_exec_finished_hid(finished_data_size);
    }
    else if (status == PICOKEY_ERR_BLOCKED) {
        send_keepalive();
    }
    if (hid_tx[ITF_HID_CTAP].w_ptr > hid_tx[ITF_HID_CTAP].r_ptr && last_write_result[ITF_HID_CTAP] != WRITE_PENDING) {
        if (driver_write_hid(ITF_HID_CTAP, hid_tx[ITF_HID_CTAP].buffer + hid_tx[ITF_HID_CTAP].r_ptr, 64) > 0) {

        }
    }
#ifndef ENABLE_EMULATION
    /* Keyboard ITF */
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
#endif
}
