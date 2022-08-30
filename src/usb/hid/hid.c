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
#include "u2f_hid.h"
#include "hsm.h"
#include "hsm_version.h"
#include "apdu.h"
#include "usb.h"

static bool mounted = false;

void tud_mount_cb()
{
    mounted = true;
}

bool driver_mounted() {
    return mounted;
}

U2FHID_FRAME *u2f_req, *u2f_resp;

int driver_init() {
    tud_init(BOARD_TUD_RHPORT);
    u2f_req = (U2FHID_FRAME *)usb_get_rx();
    apdu.header = u2f_req->init.data;

    u2f_resp = (U2FHID_FRAME *)usb_get_tx();
    apdu.rdata = u2f_resp->init.data;

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

int driver_write(const uint8_t *buffer, size_t buffer_size) {
    return tud_hid_report(0, buffer, buffer_size);
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

void hid_write_offset(uint16_t size, uint16_t offset) {
    if (*usb_get_tx() != 0x81)
        DEBUG_PAYLOAD(usb_get_tx()+offset,size+10);
    usb_write_offset(size, offset);
}

void hid_write(uint16_t size) {
    hid_write_offset(size, 0);
}

int driver_process_usb_packet(uint16_t read) {
    if (read >= 10)
    {
        if (FRAME_TYPE(u2f_req) == TYPE_INIT) {
            printf("command %x\n", FRAME_CMD(u2f_req));
            printf("len %d\n", MSG_LEN(u2f_req));
            DEBUG_PAYLOAD(u2f_req->init.data, MSG_LEN(u2f_req));
        }
        if (u2f_req->init.cmd == U2FHID_INIT) {
            U2FHID_INIT_REQ *req = (U2FHID_INIT_REQ *)u2f_req->init.data;
            U2FHID_INIT_RESP *resp = (U2FHID_INIT_RESP *)u2f_resp->init.data;
            memcpy(resp->nonce, req->nonce, sizeof(resp->nonce));
            resp->cid = 0x01000000;
            resp->versionInterface = U2FHID_IF_VERSION;
            resp->versionMajor = HSM_SDK_VERSION_MAJOR;
            resp->versionMinor = HSM_SDK_VERSION_MINOR;
            resp->capFlags = CAPFLAG_WINK;

            u2f_resp->cid = CID_BROADCAST;
            u2f_resp->init.cmd = U2FHID_INIT;
            u2f_resp->init.bcntl = 17;
            u2f_resp->init.bcnth = 0;
            hid_write(64);
            DEBUG_PAYLOAD((uint8_t *)u2f_resp, u2f_resp->init.bcntl+7);
        }
        // echo back anything we received from host
        //tud_hid_report(0, buffer, bufsize);
        printf("END\n");
        usb_clear_rx();
    }
    return 0;
}

void driver_exec_timeout() {

}

void driver_exec_finished(size_t size_next) {

}
