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

#include "tusb.h"
#include "ctap_hid.h"
#include "hsm.h"
#include "hsm_version.h"
#include "apdu.h"
#include "usb.h"
#include "bsp/board.h"
#include "cbor.h"

#define CTAP_MAX_PACKET_SIZE (64 - 7 + 128 * (64 - 5))

static bool mounted = false;

typedef struct msg_packet {
    uint16_t len;
    uint16_t current_len;
    uint8_t data[CTAP_MAX_PACKET_SIZE];
} __packed msg_packet_t;

msg_packet_t msg_packet = { 0 };

void tud_mount_cb()
{
    mounted = true;
}

bool driver_mounted() {
    return mounted;
}

CTAPHID_FRAME *ctap_req = NULL, *ctap_resp = NULL;

int driver_init() {
    tud_init(BOARD_TUD_RHPORT);
    ctap_req = (CTAPHID_FRAME *)usb_get_rx();
    apdu.header = ctap_req->init.data;

    ctap_resp = (CTAPHID_FRAME *)usb_get_tx();
    apdu.rdata = ctap_resp->init.data;

    return 0;
}
void driver_task() {
    tud_task(); // tinyusb device task
}
//--------------------------------------------------------------------+
// USB HID
//--------------------------------------------------------------------+

// Invoked when received GET_REPORT control request
// Application must fill buffer report's content and return its length.
// Return zero will cause the stack to STALL request
uint16_t tud_hid_get_report_cb(uint8_t itf, uint8_t report_id, hid_report_type_t report_type, uint8_t* buffer, uint16_t reqlen)
{
  // TODO not Implemented
  (void) itf;
  (void) report_id;
  (void) report_type;
  (void) buffer;
  (void) reqlen;
  printf("get_report\n");
  DEBUG_PAYLOAD(buffer, reqlen);

  return 0;
}

void hid_write_offset(uint16_t size, uint16_t offset) {
    if (*usb_get_tx() != 0x81)
        DEBUG_PAYLOAD(usb_get_tx()+offset, size);
    usb_write_offset(size, offset);
}

void hid_write(uint16_t size) {
    hid_write_offset(size, 0);
}

uint16_t send_buffer_size = 0;

void tud_hid_report_complete_cb(uint8_t instance, uint8_t const* report, /*uint16_t*/ uint8_t len) {
    uint8_t seq = report[4] & TYPE_MASK ? 0 : report[4]+1;
    if (send_buffer_size > 0)
    {
        ctap_resp->cid = ctap_req->cid;
        ctap_resp->cont.seq = seq;
        hid_write_offset(64, (uint8_t *)ctap_resp - (usb_get_tx()));
        send_buffer_size -= MIN(64 - 5, send_buffer_size);
        ctap_resp = (CTAPHID_FRAME *)((uint8_t *)ctap_resp + 64 - 5);
    }
}

int driver_write(const uint8_t *buffer, size_t buffer_size) {
    int ret = tud_hid_report(0, buffer, buffer_size);
    return ret;
}

size_t driver_read(uint8_t *buffer, size_t buffer_size) {
    return 0;
}

// Invoked when received SET_REPORT control request or
// received data on OUT endpoint ( Report ID = 0, Type = 0 )
void tud_hid_set_report_cb(uint8_t itf, uint8_t report_id, hid_report_type_t report_type, uint8_t const* buffer, uint16_t bufsize)
{
  // This example doesn't use multiple report and report ID
  (void) itf;
  (void) report_id;
  (void) report_type;
  printf("set report\n");
  usb_rx(buffer, bufsize);
}

int ctap_error(uint8_t error) {
    ctap_resp = (CTAPHID_FRAME *)usb_get_tx();
    memset(ctap_resp, 0, sizeof(CTAPHID_FRAME));
    ctap_resp->cid = ctap_req->cid;
    ctap_resp->init.cmd = CTAPHID_ERROR;
    ctap_resp->init.bcntl = 1;
    ctap_resp->init.data[0] = error;
    hid_write(64);
    usb_clear_rx();
    return 0;
}

uint8_t last_cmd = 0;
uint8_t last_seq = 0;
CTAPHID_FRAME last_req = { 0 };
uint32_t lock = 0;

const uint8_t aaguid[16] = {0x89, 0xFB, 0x94, 0xB7, 0x06, 0xC9, 0x36, 0x73, 0x9B, 0x7E, 0x30, 0x52, 0x6D, 0x96, 0x81, 0x45}; // First 16 bytes of SHA256("Pico FIDO2")

int cbor_make_credential(const uint8_t *data, size_t len) {
    return 0;
}

#define CHECK_CBOR(f)           \
    do                          \
    {                           \
        CborError err = f;      \
        if (err != CborNoError) \
        {                       \
            printf("Cannot encode CBOR: %s\n", #f); \
            return err; \
        } \
    } while (0)

int cbor_get_info() {
    CborEncoder encoder, mapEncoder, arrayEncoder;
    cbor_encoder_init(&encoder, ctap_resp->init.data + 1, CTAP_MAX_PACKET_SIZE, 0);
    CHECK_CBOR(cbor_encoder_create_map(&encoder, &mapEncoder, 7));

    CHECK_CBOR(cbor_encode_simple_value(&mapEncoder, 0x01));
    CHECK_CBOR(cbor_encoder_create_array(&mapEncoder, &arrayEncoder, 2));
    CHECK_CBOR(cbor_encode_text_stringz(&arrayEncoder, "U2F_V2"));
    CHECK_CBOR(cbor_encode_text_stringz(&arrayEncoder, "FIDO_2_0"));
    CHECK_CBOR(cbor_encoder_close_container(&mapEncoder, &arrayEncoder));

    CHECK_CBOR(cbor_encode_simple_value(&mapEncoder, 0x02));
    CHECK_CBOR(cbor_encoder_create_array(&mapEncoder, &arrayEncoder, 1));
    CHECK_CBOR(cbor_encode_text_stringz(&arrayEncoder, "hmac-secret"));
    CHECK_CBOR(cbor_encoder_close_container(&mapEncoder, &arrayEncoder));

    CHECK_CBOR(cbor_encode_simple_value(&mapEncoder, 0x03));
    CHECK_CBOR(cbor_encode_byte_string(&mapEncoder, aaguid, sizeof(aaguid)));

    CHECK_CBOR(cbor_encode_simple_value(&mapEncoder, 0x04));
    CHECK_CBOR(cbor_encoder_create_map(&mapEncoder, &arrayEncoder, 3));
    CHECK_CBOR(cbor_encode_text_stringz(&arrayEncoder, "rk"));
    CHECK_CBOR(cbor_encode_boolean(&arrayEncoder, true));
    CHECK_CBOR(cbor_encode_text_stringz(&arrayEncoder, "up"));
    CHECK_CBOR(cbor_encode_boolean(&arrayEncoder, true));
    CHECK_CBOR(cbor_encode_text_stringz(&arrayEncoder, "uv"));
    CHECK_CBOR(cbor_encode_boolean(&arrayEncoder, true));
    CHECK_CBOR(cbor_encoder_close_container(&mapEncoder, &arrayEncoder));

    CHECK_CBOR(cbor_encode_simple_value(&mapEncoder, 0x06));
    CHECK_CBOR(cbor_encoder_create_array(&mapEncoder, &arrayEncoder, 1));
    CHECK_CBOR(cbor_encode_simple_value(&arrayEncoder, 1)); // PIN protocols
    CHECK_CBOR(cbor_encoder_close_container(&mapEncoder, &arrayEncoder));

    CHECK_CBOR(cbor_encode_simple_value(&mapEncoder, 0x07));
    CHECK_CBOR(cbor_encoder_create_array(&mapEncoder, &arrayEncoder, 1));
    CHECK_CBOR(cbor_encode_simple_value(&arrayEncoder, 10)); // MAX_CRED_COUNT_IN_LIST
    CHECK_CBOR(cbor_encoder_close_container(&mapEncoder, &arrayEncoder));

    CHECK_CBOR(cbor_encode_simple_value(&mapEncoder, 0x08));
    CHECK_CBOR(cbor_encoder_create_array(&mapEncoder, &arrayEncoder, 1));
    CHECK_CBOR(cbor_encode_uint(&arrayEncoder, 1024)); // CRED_ID_MAX_LENGTH
    CHECK_CBOR(cbor_encoder_close_container(&mapEncoder, &arrayEncoder));

    CHECK_CBOR(cbor_encoder_close_container(&encoder, &mapEncoder));
    size_t rs = cbor_encoder_get_buffer_size(&encoder, ctap_resp->init.data + 1);
    driver_exec_finished(rs + 1);
    return 0;
}

int cbor_process(const uint8_t *data, size_t len) {
    if (len == 0)
        return -ERR_INVALID_LEN;
    driver_prepare_response();
    if (data[0] == CTAP_MAKE_CREDENTIAL)
        return cbor_make_credential(data + 1, len - 1);
    else if (data[0] == CTAP_GET_INFO)
        return cbor_get_info();
    return -ERR_INVALID_PAR;
}

int driver_process_usb_packet(uint16_t read) {
    int apdu_sent = 0;
    if (read >= 5)
    {
        DEBUG_PAYLOAD(usb_get_rx(),64);
        memset(ctap_resp, 0, sizeof(CTAPHID_FRAME));
        if (ctap_req->cid == 0x0 || (ctap_req->cid == CID_BROADCAST && ctap_req->init.cmd != CTAPHID_INIT))
            return ctap_error(ERR_INVALID_CHANNEL);
        if (board_millis() < lock && ctap_req->cid != last_req.cid)
            return ctap_error(ERR_CHANNEL_BUSY);
        if (FRAME_TYPE(ctap_req) == TYPE_INIT)
        {
            if (MSG_LEN(ctap_req) > CTAP_MAX_PACKET_SIZE)
                return ctap_error(ERR_INVALID_LEN);
            if (msg_packet.len > 0 && last_req.cid != ctap_req->cid) //We are in a transaction
                return ctap_error(ERR_CHANNEL_BUSY);
            printf("command %x\n", FRAME_CMD(ctap_req));
            printf("len %d\n", MSG_LEN(ctap_req));
            msg_packet.len = msg_packet.current_len = 0;
            if (MSG_LEN(ctap_req) > 64 - 7)
            {
                msg_packet.len = MSG_LEN(ctap_req);
                memcpy(msg_packet.data + msg_packet.current_len, ctap_req->init.data, 64-7);
                msg_packet.current_len += 64 - 7;
            }
            memcpy(&last_req, ctap_req, sizeof(CTAPHID_FRAME));
            last_cmd = ctap_req->init.cmd;
            last_seq = 0;
        }
        else {
            if (msg_packet.len == 0) //Received a cont with a prior init pkt
                return 0;
            if (last_seq != ctap_req->cont.seq)
                return ctap_error(ERR_INVALID_SEQ);
            if (last_req.cid == ctap_req->cid) {
                memcpy(msg_packet.data + msg_packet.current_len, ctap_req->cont.data, MIN(64 - 5, msg_packet.len - msg_packet.current_len));
                msg_packet.current_len += MIN(64 - 5, msg_packet.len - msg_packet.current_len);
                memcpy(&last_req, ctap_req, sizeof(CTAPHID_FRAME));
            }
            //else // Received a cont from another channel. Silently discard
            last_seq++;
        }

        if (ctap_req->init.cmd == CTAPHID_INIT) {
            ctap_resp = (CTAPHID_FRAME *)usb_get_tx();
            CTAPHID_INIT_REQ *req = (CTAPHID_INIT_REQ *)ctap_req->init.data;
            CTAPHID_INIT_RESP *resp = (CTAPHID_INIT_RESP *)ctap_resp->init.data;
            memcpy(resp->nonce, req->nonce, sizeof(resp->nonce));
            resp->cid = 0x01000000;
            resp->versionInterface = CTAPHID_IF_VERSION;
            resp->versionMajor = HSM_SDK_VERSION_MAJOR;
            resp->versionMinor = HSM_SDK_VERSION_MINOR;
            resp->capFlags = CAPFLAG_WINK | CAPFLAG_CBOR;

            ctap_resp->cid = CID_BROADCAST;
            ctap_resp->init.cmd = CTAPHID_INIT;
            ctap_resp->init.bcntl = 17;
            ctap_resp->init.bcnth = 0;
            hid_write(64);
            current_app = apps[0].select_aid(&apps[0]);
            card_start();
            DEBUG_PAYLOAD((uint8_t *)ctap_resp, ctap_resp->init.bcntl+7);
        }
        else if (ctap_req->init.cmd == CTAPHID_WINK) {
            if (MSG_LEN(ctap_req) != 0) {
                return ctap_error(ERR_INVALID_LEN);
            }
            ctap_resp = (CTAPHID_FRAME *)usb_get_tx();
            memcpy(ctap_resp, ctap_req, sizeof(CTAPHID_FRAME));
            sleep_ms(1000); //For blinking the device during 1 seg
            hid_write(64);
        }
        else if (ctap_req->init.cmd == CTAPHID_PING || ctap_req->init.cmd == CTAPHID_SYNC) {
            ctap_resp = (CTAPHID_FRAME *)usb_get_tx();
            memcpy(ctap_resp, ctap_req, sizeof(CTAPHID_FRAME));
            hid_write(64);
        }
        else if (ctap_req->init.cmd == CTAPHID_LOCK) {
            if (MSG_LEN(ctap_req) != 1)
                return ctap_error(ERR_INVALID_LEN);
            if (ctap_req->init.data[0] > 10)
                return ctap_error(ERR_INVALID_PAR);
            lock = board_millis() + ctap_req->init.data[0] * 1000;
            ctap_resp = (CTAPHID_FRAME *)usb_get_tx();
            memset(ctap_resp, 0, 64);
            ctap_resp->cid = ctap_req->cid;
            ctap_resp->init.cmd = ctap_req->init.cmd;
            hid_write(64);
        }
        else if ((ctap_req->init.cmd == CTAPHID_MSG && msg_packet.len == 0) || (msg_packet.len == msg_packet.current_len && msg_packet.len > 0)) {
            if (msg_packet.current_len == msg_packet.len && msg_packet.len > 0)
                apdu_sent = apdu_process(msg_packet.data, msg_packet.len);
            else
                apdu_sent = apdu_process(ctap_req->init.data, MSG_LEN(ctap_req));
            DEBUG_PAYLOAD(apdu.data, (int)apdu.nc);
            msg_packet.len = msg_packet.current_len = 0; //Reset the transaction
        }
        else if ((ctap_req->init.cmd == CTAPHID_CBOR && msg_packet.len == 0) || (msg_packet.len == msg_packet.current_len && msg_packet.len > 0)) {
            if (msg_packet.current_len == msg_packet.len && msg_packet.len > 0)
                apdu_sent = cbor_process(msg_packet.data, msg_packet.len);
            else
                apdu_sent = cbor_process(ctap_req->init.data, MSG_LEN(ctap_req));
            msg_packet.len = msg_packet.current_len = 0; //Reset the transaction
            if (apdu_sent < 0)
                return ctap_error(-apdu_sent);
        }
        else {
            if (msg_packet.len == 0)
                return ctap_error(ERR_INVALID_CMD);
        }
        // echo back anything we received from host
        //tud_hid_report(0, buffer, bufsize);
        printf("END\n");
        usb_clear_rx();
    }
    return apdu_sent;
}

void driver_exec_timeout() {

}

uint8_t *driver_prepare_response() {
    ctap_resp = (CTAPHID_FRAME *)usb_get_tx();
    apdu.rdata = ctap_resp->init.data;
    memset(usb_get_tx(), 0, 4096);
    return ctap_resp->init.data;
}

void driver_exec_finished(size_t size_next) {
    driver_exec_finished_cont(size_next, 7);
}

void driver_exec_finished_cont(size_t size_next, size_t offset) {
    offset -= 7;
    ctap_resp = (CTAPHID_FRAME *)(usb_get_tx() + offset);
    ctap_resp->cid = ctap_req->cid;
    ctap_resp->init.cmd = last_cmd;
    ctap_resp->init.bcnth = size_next >> 8;
    ctap_resp->init.bcntl = size_next & 0xff;
    hid_write_offset(64, offset);
    ctap_resp = (CTAPHID_FRAME *)((uint8_t *)ctap_resp + 64 - 5);

    send_buffer_size = size_next;
    send_buffer_size -= MIN(64-7, send_buffer_size);
}
