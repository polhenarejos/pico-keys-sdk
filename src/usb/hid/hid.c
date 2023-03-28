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

#ifndef ENABLE_EMULATION
#include "tusb.h"
#include "bsp/board.h"
#endif
#include "ctap_hid.h"
#include "hsm.h"
#include "hsm_version.h"
#include "apdu.h"
#include "usb.h"

static bool mounted = false;
extern int cbor_process(uint8_t, const uint8_t *, size_t);
extern void init_fido();

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

    return 0;
}

uint16_t send_buffer_size[ITF_TOTAL] = {0};
bool last_write_result[ITF_TOTAL] = {false};

uint8_t otp_frame_rx[70] = {0};
uint8_t otp_frame_tx[70] = {0};
uint8_t otp_exp_seq = 0, otp_curr_seq = 0;
uint8_t otp_header[4] = {0};

uint16_t calculate_crc(const uint8_t *data, size_t data_len) {
    uint16_t crc = 0xFFFF;
    for (size_t idx = 0; idx < data_len; idx++) {
        crc ^= data[idx];
        for (uint8_t i = 0; i < 8; i++) {
            uint16_t j = crc & 0x1;
            crc >>= 1;
            if (j == 1) {
                crc ^= 0x8408;
            }
        }
    }
    return crc & 0xFFFF;
}

int otp_send_frame(uint8_t *frame, size_t frame_len) {
    uint16_t crc = calculate_crc(frame, frame_len);
    frame[frame_len] = ~crc & 0xff;
    frame[frame_len + 1] = ~crc >> 8;
    frame_len += 2;
    send_buffer_size[ITF_KEYBOARD] = frame_len;
    otp_exp_seq = (frame_len / 7);
    if (frame_len % 7) {
        otp_exp_seq++;
    }
    otp_curr_seq = 0;
    return 0;
}

//--------------------------------------------------------------------+
// USB HID
//--------------------------------------------------------------------+

#ifndef ENABLE_EMULATION
// Invoked when received GET_REPORT control request
// Application must fill buffer report's content and return its length.
// Return zero will cause the stack to STALL request
extern uint16_t otp_status();
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
    //printf("get_report %d %d %d\n", itf, report_id, report_type);
    //DEBUG_PAYLOAD(buffer, reqlen);
    if (send_buffer_size[ITF_KEYBOARD] > 0) {
        uint8_t seq = otp_curr_seq++;
        memset(buffer, 0, 8);
        memcpy(buffer, otp_frame_tx + 7 * seq, MIN(7, send_buffer_size[ITF_KEYBOARD]));
        buffer[7] = 0x40 | seq;
        DEBUG_DATA(buffer, 8);
        send_buffer_size[ITF_KEYBOARD] -= MIN(7, send_buffer_size[ITF_KEYBOARD]);
    }
    else if (otp_curr_seq == otp_exp_seq && otp_exp_seq > 0) {
        memset(buffer, 0, 7);
        buffer[7] = 0x40;
        DEBUG_DATA(buffer,8);
        otp_curr_seq = otp_exp_seq = 0;
    }
    else {
        otp_status();
        memcpy(buffer, res_APDU, 7);
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

void add_keyboard_buffer(const uint8_t *data, size_t data_len) {
    keyboard_buffer_len = MIN(sizeof(keyboard_buffer), data_len);
    memcpy(keyboard_buffer, data, keyboard_buffer_len);
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
                    if (conv_table[chr][0]) {
                        modifier = KEYBOARD_MODIFIER_LEFTSHIFT;
                    }
                    keycode[0] = conv_table[chr][1];
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
int driver_write_hid(uint8_t itf, const uint8_t *buffer, size_t buffer_size) {
    last_write_result[itf] = tud_hid_n_report(itf, 0, buffer, buffer_size);
    printf("result %d\n", last_write_result[itf]);
    if (last_write_result[itf] == false) {
        return 0;
    }
    return MIN(64, buffer_size);
}
#endif

size_t driver_read_hid(uint8_t *buffer, size_t buffer_size) {
    return 0;
}

#ifndef ENABLE_EMULATION
// Invoked when received SET_REPORT control request or
// received data on OUT endpoint ( Report ID = 0, Type = 0 )

extern int otp_process_apdu();
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
    //printf("set_report %d %d %d\n", itf, report_id, report_type);
    if (itf == ITF_KEYBOARD && report_type == 3) {
        //DEBUG_PAYLOAD(buffer, bufsize);
        if (buffer[7] == 0xFF) { // reset
            send_buffer_size[ITF_KEYBOARD] = 0;
            otp_curr_seq = otp_exp_seq = 0;
            memset(otp_frame_tx, 0, sizeof(otp_frame_tx));
        }
        else if (buffer[7] & 0x80) { // a frame
            uint8_t rseq = buffer[7] & 0x1F;
            if (rseq < 10) {
                if (rseq == 0) {
                    memset(otp_frame_rx, 0, sizeof(otp_frame_rx));
                }
                memcpy(otp_frame_rx + rseq * 7, buffer, 7);
                if (rseq == 9) {
                    DEBUG_DATA(otp_frame_rx, sizeof(otp_frame_rx));
                    uint16_t residual_crc = calculate_crc(otp_frame_rx, 64), rcrc = (otp_frame_rx[66] << 8 | otp_frame_rx[65]);
                    uint8_t slot_id = otp_frame_rx[64];
                    if (residual_crc == rcrc) {
                        apdu.data = otp_frame_rx;
                        apdu.nc = 64;
                        apdu.rdata = otp_frame_tx;
                        apdu.header[1] = 0x01;
                        apdu.header[2] = slot_id;
                        int ret = otp_process_apdu();
                        if (ret == 0x9000 && res_APDU_size > 0) {
                            otp_send_frame(apdu.rdata, apdu.rlen);
                        }
                    }
                    else {
                        printf("[OTP] Bad CRC!\n");
                    }
                }
            }
        }
    }
    else
        usb_rx(itf, buffer, bufsize);
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
extern void cbor_thread();
extern bool cancel_button;

int driver_process_usb_nopacket_hid() {
    if (last_packet_time > 0 && last_packet_time + 500 < board_millis()) {
        ctap_error(CTAP1_ERR_MSG_TIMEOUT);
        last_packet_time = 0;
        msg_packet.len = msg_packet.current_len = 0;
    }
    return 0;
}

extern const uint8_t fido_aid[];

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
            init_fido();
            ctap_resp = (CTAPHID_FRAME *) usb_get_tx(ITF_HID);
            memset(ctap_resp, 0, 64);
            CTAPHID_INIT_REQ *req = (CTAPHID_INIT_REQ *) ctap_req->init.data;
            CTAPHID_INIT_RESP *resp = (CTAPHID_INIT_RESP *) ctap_resp->init.data;
            memcpy(resp->nonce, req->nonce, sizeof(resp->nonce));
            resp->cid = 0x01000000;
            resp->versionInterface = CTAPHID_IF_VERSION;
            resp->versionMajor = HSM_SDK_VERSION_MAJOR;
            resp->versionMinor = HSM_SDK_VERSION_MINOR;
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
        else if (last_cmd == CTAPHID_MSG &&
                 (msg_packet.len == 0 ||
                  (msg_packet.len == msg_packet.current_len && msg_packet.len > 0))) {

            if (current_app == NULL ||
                memcmp(current_app->aid, fido_aid + 1,
                       MIN(current_app->aid[0], fido_aid[0])) != 0) {
                for (int a = 0; a < num_apps; a++) {
                    if ((current_app = apps[a].select_aid(&apps[a], fido_aid + 1, fido_aid[0]))) {
                        break;
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
            card_start(cbor_thread);
#endif
            thread_type = 2;
            if (msg_packet.current_len == msg_packet.len && msg_packet.len > 0) {
                apdu_sent = cbor_process(last_cmd, msg_packet.data, msg_packet.len);
            }
            else {
                apdu_sent = cbor_process(last_cmd, ctap_req->init.data, MSG_LEN(ctap_req));
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

void driver_exec_finished_hid(size_t size_next) {
    if (size_next > 0) {
        if (thread_type == 2 && apdu.sw != 0) {
            ctap_error(apdu.sw & 0xff);
        }
        else {
            driver_exec_finished_cont_hid(size_next, 7);
        }
    }
    apdu.sw = 0;
}

void driver_exec_finished_cont_hid(size_t size_next, size_t offset) {
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
