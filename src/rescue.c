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

#include "pico_keys.h"
#include "apdu.h"
#include "version.h"

int rescue_process_apdu();
int rescue_unload();

const uint8_t rescue_aid[] = {
    8,
    0xA0, 0x58, 0x3F, 0xC1, 0x9B, 0x7E, 0x4F, 0x21
};

int rescue_select(app_t *a, uint8_t force) {
    a->process_apdu = rescue_process_apdu;
    a->unload = rescue_unload;
    memcpy(res_APDU, PICO_SDK_VERSION_STRING, strlen(PICO_SDK_VERSION_STRING));
    res_APDU_size = (uint16_t)strlen((char *) res_APDU);
    apdu.ne = res_APDU_size;
    if (force) {
        scan_flash();
    }
    return CCID_OK;
}

INITIALIZER ( rescue_ctor ) {
    register_app(rescue_select, rescue_aid);
}

int rescue_unload() {
    return CCID_OK;
}

int cmd_write() {
    if (apdu.nc < 2) {
        return SW_WRONG_LENGTH();
    }

    if (P1(apdu) == 0x1) { // PHY
#ifndef ENABLE_EMULATION
        int ret = phy_unserialize_data(apdu.data, apdu.nc, &phy_data);
        if (ret == CCID_OK) {
            file_put_data(ef_phy, apdu.data, apdu.nc);
        }
#endif
    }
    low_flash_available();
    return SW_OK();
}

#define INS_WRITE            0x1C

static const cmd_t cmds[] = {
    { INS_WRITE, cmd_write },
    { 0x00, 0x0 }
};

int rescue_process_apdu() {
    if (CLA(apdu) != 0x80) {
        return SW_CLA_NOT_SUPPORTED();
    }
    for (const cmd_t *cmd = cmds; cmd->ins != 0x00; cmd++) {
        if (cmd->ins == INS(apdu)) {
            int r = cmd->cmd_handler();
            return r;
        }
    }
    return SW_INS_NOT_SUPPORTED();
}
