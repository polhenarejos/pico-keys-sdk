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
#include "pico_keys_version.h"
#include "otp.h"

int rescue_process_apdu();
int rescue_unload();

const uint8_t rescue_aid[] = {
    8,
    0xA0, 0x58, 0x3F, 0xC1, 0x9B, 0x7E, 0x4F, 0x21
};

#ifdef PICO_RP2350
#define PICO_MCU 1
#elif defined(ESP_PLATFORM)
#define PICO_MCU 2
#else
#define PICO_MCU 0
#endif

extern uint8_t PICO_PRODUCT;

int rescue_select(app_t *a, uint8_t force) {
    a->process_apdu = rescue_process_apdu;
    a->unload = rescue_unload;
    res_APDU_size = 0;
    res_APDU[res_APDU_size++] = PICO_MCU;
    res_APDU[res_APDU_size++] = PICO_PRODUCT;
    res_APDU[res_APDU_size++] = PICO_KEYS_SDK_VERSION_MAJOR;
    res_APDU[res_APDU_size++] = PICO_KEYS_SDK_VERSION_MINOR;
    apdu.ne = res_APDU_size;
    if (force) {
        scan_flash();
    }
    return PICOKEY_OK;
}

INITIALIZER ( rescue_ctor ) {
    register_app(rescue_select, rescue_aid);
}

int rescue_unload() {
    return PICOKEY_OK;
}

int cmd_write() {
    if (apdu.nc < 2) {
        return SW_WRONG_LENGTH();
    }

    if (P1(apdu) == 0x1) { // PHY
#ifndef ENABLE_EMULATION
        int ret = phy_unserialize_data(apdu.data, apdu.nc, &phy_data);
        if (ret == PICOKEY_OK) {
            if (phy_save() != PICOKEY_OK) {
                return SW_EXEC_ERROR();
            }
        }
#endif
    }
    return SW_OK();
}

#if defined(PICO_RP2350) || defined(ESP_PLATFORM)
int cmd_secure() {
    if (apdu.nc != 0) {
        return SW_WRONG_LENGTH();
    }

    uint8_t bootkey = P1(apdu);
    bool secure_lock = P2(apdu) == 0x1;

    int ret = otp_enable_secure_boot(bootkey, secure_lock);
    if (ret != 0) {
        return SW_EXEC_ERROR();
    }
    return SW_OK();
}
#endif

#define INS_WRITE            0x1C
#define INS_SECURE           0x1D

static const cmd_t cmds[] = {
    { INS_WRITE, cmd_write },
#if defined(PICO_RP2350) || defined(ESP_PLATFORM)
    { INS_SECURE, cmd_secure },
#endif
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
