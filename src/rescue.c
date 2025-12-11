/*
 * This file is part of the Pico Keys SDK distribution (https://github.com/polhenarejos/pico-keys-sdk).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "pico_keys.h"
#include "apdu.h"
#include "pico_keys_version.h"
#include "otp.h"
#ifdef PICO_PLATFORM
#include "pico/bootrom.h"
#include "hardware/watchdog.h"
#endif

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
#elif defined(ENABLE_EMULATION)
#define PICO_MCU 3
#else
#define PICO_MCU 0
#endif

extern uint8_t PICO_PRODUCT;
extern uint8_t PICO_VERSION_MAJOR;
extern uint8_t PICO_VERSION_MINOR;

int rescue_select(app_t *a, uint8_t force) {
    a->process_apdu = rescue_process_apdu;
    a->unload = rescue_unload;
    res_APDU_size = 0;
    res_APDU[res_APDU_size++] = PICO_MCU;
    res_APDU[res_APDU_size++] = PICO_PRODUCT;
    res_APDU[res_APDU_size++] = PICO_VERSION_MAJOR;
    res_APDU[res_APDU_size++] = PICO_VERSION_MINOR;
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
        int ret = phy_unserialize_data(apdu.data, (uint16_t)apdu.nc, &phy_data);
        if (ret == PICOKEY_OK) {
            if (phy_save() != PICOKEY_OK) {
                return SW_EXEC_ERROR();
            }
        }
#endif
    }
    return SW_OK();
}

int cmd_read() {
    if (apdu.nc != 0) {
        return SW_WRONG_LENGTH();
    }

    uint8_t p1 = P1(apdu);
    if (p1 == 0x1) { // PHY
#ifndef ENABLE_EMULATION
        uint16_t len = 0;
        int ret = phy_serialize_data(&phy_data, apdu.rdata, &len);
        if (ret != PICOKEY_OK) {
            return SW_EXEC_ERROR();
        }
        res_APDU_size = len;
#endif
    }
    else if (p1 == 0x2) { // FLASH INFO
        res_APDU_size = 0;
        uint32_t free = flash_free_space(), total = flash_total_space(), used = flash_used_space(), nfiles = flash_num_files(), size = flash_size();
        res_APDU_size += put_uint32_t_be(free, res_APDU + res_APDU_size);
        res_APDU_size += put_uint32_t_be(used, res_APDU + res_APDU_size);
        res_APDU_size += put_uint32_t_be(total, res_APDU + res_APDU_size);
        res_APDU_size += put_uint32_t_be(nfiles, res_APDU + res_APDU_size);
        res_APDU_size += put_uint32_t_be(size, res_APDU + res_APDU_size);
    }
    else if (p1 == 0x3) { // OTP SECURE BOOT STATUS
        res_APDU_size = 0;
        uint8_t bootkey = 0xFF;
        bool enabled = otp_is_secure_boot_enabled(&bootkey);
        bool locked = otp_is_secure_boot_locked();
        res_APDU[res_APDU_size++] = enabled ? 0x1 : 0x0;
        res_APDU[res_APDU_size++] = locked ? 0x1 : 0x0;
        res_APDU[res_APDU_size++] = bootkey;
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

#ifdef PICO_PLATFORM
int cmd_reboot_bootsel() {
    if (apdu.nc != 0) {
        return SW_WRONG_LENGTH();
    }

    if (P1(apdu) == 0x1) {
        // Reboot to BOOTSEL
        reset_usb_boot(0, 0);
    }
    else if (P1(apdu) == 0x0) {
        // Reboot to normal mode
        watchdog_reboot(0, 0, 100);
    }
    else {
        return SW_INCORRECT_P1P2();
    }

    return SW_OK();
}
#endif

#define INS_WRITE            0x1C
#define INS_SECURE           0x1D
#define INS_READ             0x1E
#define INS_REBOOT_BOOTSEL   0x1F

static const cmd_t cmds[] = {
    { INS_WRITE, cmd_write },
#if defined(PICO_RP2350) || defined(ESP_PLATFORM)
    { INS_SECURE, cmd_secure },
#endif
    { INS_READ, cmd_read },
#ifdef PICO_PLATFORM
    { INS_REBOOT_BOOTSEL, cmd_reboot_bootsel },
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
